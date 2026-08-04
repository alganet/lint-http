// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageTransferEncodingChunkedFinal;

impl Rule for MessageTransferEncodingChunkedFinal {
    fn id(&self) -> &'static str {
        "message_transfer_encoding_chunked_final"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Collect the coding names in wire order across every field line.
        //
        // `None` means the value could not be read as a list at all: quoting
        // that never closes leaves every later comma inside it, and an order
        // derived from members that cannot be delimited would be a guess.
        // Unlike the ordering questions below, that one has an owner --
        // `message_transfer_coding_iana_registered` reports a malformed
        // `Transfer-Encoding` -- so declining here loses nothing.
        // cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
        let collect = |headers: &hyper::HeaderMap| -> Option<Vec<String>> {
            let mut codings: Vec<String> = Vec::new();
            for hv in headers.get_all(hyper::header::TRANSFER_ENCODING).iter() {
                // Decoded from the raw octets. `to_str` refuses everything
                // outside visible US-ASCII, and a single such byte -- legal in
                // this grammar only inside a `quoted-string` in a parameter
                // value, which this rule never reads -- used to drop the whole
                // field line. Dropping a line here does not merely miss a
                // finding: it silently reorders the sequence this rule exists
                // to judge, because the codings on that line are the ones
                // between the lines that remain.
                let val = String::from_utf8_lossy(hv.as_bytes());
                if !crate::helpers::headers::quoting_is_balanced(&val) {
                    return None;
                }
                // Quote-aware: a comma inside a transfer-parameter's
                // quoted-string value is not a list separator.
                // cite(RFC 9110 § 10.1.4): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
                for part in crate::helpers::headers::split_commas_respecting_quotes(&val) {
                    let part = part.trim();
                    // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
                    if part.is_empty() {
                        continue;
                    }
                    // The name, not the member. The old code pushed the whole
                    // member, so `chunked;ext=1` never equalled `"chunked"` and
                    // a parameterised chunked in a non-final position was
                    // invisible to every check below -- the one place where
                    // being lax about parameters changes the answer rather than
                    // just the message. Whether the parameter should be there at
                    // all is `message_transfer_coding_iana_registered`'s finding.
                    // cite(RFC 9110 § 10.1.4): "transfer-coding    = token *( OWS ";" OWS transfer-parameter )"
                    let name = part.split(';').next().unwrap().trim();
                    if name.is_empty() {
                        continue;
                    }
                    // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
                    codings.push(name.to_ascii_lowercase());
                }
            }
            Some(codings)
        };

        // Whether the message announces that the connection ends with it.
        // cite(RFC 9110 § 7.6.1): "Connection        = #connection-option connection-option = token"
        // cite(RFC 9112 § 9.6): "The "close" connection option is defined as a signal that the sender will close this connection after completion of the response."
        let announces_close = |headers: &hyper::HeaderMap| -> bool {
            headers.get_all("connection").iter().any(|hv| {
                let val = String::from_utf8_lossy(hv.as_bytes());
                // Bound rather than returned directly: the iterator borrows
                // `val`, and as a tail expression it outlives it. Not a style
                // choice -- inlining it does not compile.
                let found = crate::helpers::headers::parse_list_header(&val)
                    .any(|opt| opt.eq_ignore_ascii_case("close"));
                found
            })
        };

        let check = |headers: &hyper::HeaderMap, is_request: bool| -> Option<Violation> {
            let codings = collect(headers)?;

            if codings.is_empty() {
                return None;
            }

            // § 6.1 gives a response two ways to satisfy the same requirement,
            // and the rule knew only one of them:
            // cite(RFC 9112 § 6.1): "If any transfer coding other than chunked is applied to a response's content, the sender MUST either apply chunked as the final transfer coding or terminate the message by closing the connection."
            //
            // So `Transfer-Encoding: chunked, gzip` on a response was reported
            // as a violation of a requirement the sender may have met the other
            // way -- and it is coherent: gzip applied *after* chunked means the
            // message is not chunk-framed on the wire, which is exactly when
            // closing the connection is the framing.
            //
            // The transaction records no connection teardown, so the second
            // alternative is read from the announcement instead. **That
            // inference rests on a SHOULD, not a MUST**, and the residue is
            // stated rather than hidden: a response that closes without saying
            // so is reported here, wrongly, and is also disregarding § 9.6.
            // Narrowing further would mean dropping the response side
            // altogether, which costs more than this tolerance does.
            // cite(RFC 9112 § 9.6): "A sender SHOULD send a Connection header field (Section 7.6.1 of [HTTP]) containing the "close" connection option when it intends to close a connection."
            if !is_request && announces_close(headers) {
                return None;
            }

            // If 'chunked' appears anywhere other than the final coding it's a violation
            if let Some(pos) = codings.iter().position(|c| c == "chunked") {
                if pos != codings.len() - 1 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                        "Transfer-Encoding 'chunked' must be the final coding: codings found '{}'",
                        codings.join(", ")
                    ),
                    });
                }
            }

            // The rule was named for where `chunked` goes when it is present,
            // and so only ever asked that. § 6.1 states the requirement the
            // other way round -- it is about what must be there at all -- and
            // that half went unchecked, so a request reading
            //
            //     Transfer-Encoding: gzip
            //
            // passed. It applies a transfer coding other than chunked and never
            // frames the result, which is the case the sentence exists for.
            // (A test asserted this was fine.)
            // cite(RFC 9112 § 6.1): "If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed."
            //
            // Requests only. The response form of the sentence offers a second
            // way to satisfy it, handled below.
            if is_request
                && codings.iter().any(|c| c != "chunked")
                && codings.last().map(String::as_str) != Some("chunked")
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "A request that applies any transfer coding other than chunked must apply \
                         chunked as the final coding: codings found '{}'",
                        codings.join(", ")
                    ),
                });
            }

            None
        };

        if let Some(v) = check(&tx.request.headers, true) {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers, false) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Transfer-Encoding Chunked Final")
    }

    fn description(&self) -> &'static str {
        "Ensures that when `Transfer-Encoding` includes the `chunked` transfer coding, it appears as the final transfer coding.\n\nPer RFC 9112 §7.1, the `chunked` transfer-coding must always be the final transfer-coding applied to a message. Intermediate codecs cannot follow `chunked`, because chunked encoding is the format used to delimit the message body.\n\nIf a message includes `Transfer-Encoding: ...` values and any of them is `chunked`, then `chunked` must be the final coding in the sequence. The rule checks all `Transfer-Encoding` header fields and the order of comma-separated codings."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9112",
            section: Some("7.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1",
            note: "Transfer-Encoding",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Transfer-Encoding: gzip, chunked\n\nTransfer-Encoding: chunked",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Transfer-Encoding: chunked, gzip\n# chunked must be final\n\n# Multiple header fields where an earlier field contains chunked\n# and later fields contain other codings",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTransferEncodingChunkedFinal;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("chunked", false)]
    #[case("gzip, chunked", false)]
    #[case("chunked, gzip", true)]
    #[case("compress, chunked", false)]
    #[case("compress, chunked, gzip", true)]
    #[case("gzip, chunked, gzip", true)]
    #[case("gzip, chunked, identity", true)]
    // § 6.1: a request applying any coding other than chunked MUST apply
    // chunked last. This asserted the opposite.
    #[case("gzip, compress", true)]
    #[case("gzip", true)]
    #[case("chunked", false)]
    fn request_transfer_encoding_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "request '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "request '{}' expected no violation", value);
        }

        Ok(())
    }

    #[test]
    fn request_no_transfer_encoding_header_returns_none() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[rstest]
    #[case("chunked", false)]
    #[case("gzip, chunked", false)]
    #[case("chunked, gzip", true)]
    #[case("gzip, compress", false)]
    fn response_transfer_encoding_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", value)],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "response '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "response '{}' expected no violation", value);
        }

        Ok(())
    }

    /// § 6.1's requirement stated the way the sentence states it: not "where
    /// does chunked go" but "chunked must be there at all". The rule was named
    /// for the first question and only ever asked that one.
    #[rstest]
    #[case("gzip")]
    #[case("gzip, compress")]
    #[case("deflate;q=1")]
    fn a_request_that_never_frames_its_content_is_reported(#[case] value: &str) {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some_and(|v| v.message.contains("must apply chunked as the final coding")),
            "request {value:?} applies a coding other than chunked and never frames it"
        );
    }

    /// The sentence is conditioned on a coding *other than* chunked being
    /// applied, so a request carrying only chunked does not engage it.
    #[test]
    fn a_request_carrying_only_chunked_is_not_reported() {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "chunked",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// A response has a second way to satisfy § 6.1, and announcing the close
    /// is how it says so. Reporting it anyway was a false statement about a
    /// conforming message.
    #[rstest]
    #[case("chunked, gzip")]
    #[case("gzip")]
    fn a_response_that_announces_close_is_not_reported(#[case] te: &str) {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", te), ("connection", "close")],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{te:?} with Connection: close: {v:?}");
    }

    /// The option is a token in a list and is matched as one, not by substring.
    #[rstest]
    #[case("keep-alive, close", true)]
    #[case("CLOSE", true)]
    #[case("keep-alive", false)]
    #[case("closed", false)]
    fn the_close_option_is_matched_as_a_list_token(#[case] connection: &str, #[case] exempt: bool) {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("transfer-encoding", "chunked, gzip"),
                ("connection", connection),
            ],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(v.is_none(), exempt, "Connection: {connection:?}: {v:?}");
    }

    /// The exemption is the response's alone. A request has no second
    /// alternative in § 6.1, so its own `Connection: close` changes nothing.
    #[test]
    fn a_request_gets_no_exemption_from_announcing_close() {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "gzip"),
            ("connection", "close"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "the request MUST is unconditional");
    }

    #[test]
    fn multiple_header_fields_ordering_is_preserved() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        // Two header fields: first 'chunked', second 'gzip' -> should violate
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "gzip"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    /// A line carrying an octet outside visible US-ASCII used to be dropped,
    /// which does not merely lose a finding here -- it removes codings from the
    /// middle of the sequence whose order is the rule's whole subject. The
    /// decoded line keeps its place, so `chunked` is still seen not to be last.
    #[test]
    fn a_line_with_a_stray_octet_still_takes_its_place_in_the_sequence() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        hm.append(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_bytes(b"\xff")?,
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some(),
            "the second line was dropped and chunked read as final"
        );
        Ok(())
    }

    /// A parameterised `chunked` is still `chunked`. Pushing the whole member
    /// meant `chunked;ext=1` never matched, so it slipped past the ordering
    /// check entirely.
    #[rstest]
    #[case("chunked;ext=1, gzip")]
    #[case("chunked ; ext=1, gzip")]
    #[case("CHUNKED;ext=1, gzip")]
    fn a_parameterised_chunked_is_still_chunked(#[case] value: &str) {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "{value:?}: chunked is not final");
    }

    /// A comma inside a quoted parameter value is not a separator, so it must
    /// not manufacture a coding that follows `chunked`.
    #[test]
    fn a_comma_inside_a_quoted_parameter_value_is_not_a_separator() {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "gzip;ext=\"a,b\", chunked",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// Quoting that never closes leaves the members undelimitable, so no claim
    /// about their order is available. Declined here; the coding-name rule is
    /// the one that reports the malformed field.
    #[test]
    fn unterminated_quoting_is_declined() {
        let rule = MessageTransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "chunked;ext=\"a, gzip",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTransferEncodingChunkedFinal;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
