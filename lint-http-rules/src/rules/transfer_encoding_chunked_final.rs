// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct TransferEncodingChunkedFinal;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9112_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
    note: "Transfer-Encoding — every requirement this rule enforces is here: chunked at most once, and chunked last (unconditionally for requests, or the connection closes for responses)",
};
const RFC_9112_9_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("9.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-9.6",
    note: "The 'close' connection option — how a response announces the alternative §6.1 gives it. §9.6 makes announcing a SHOULD, which bounds what this rule can conclude",
};
const RFC_9112_7_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1",
    note: "Chunked Transfer Coding — what chunked is, and why nothing may follow it. It does NOT contain the ordering requirement this rule's SpecRef used to attribute to it",
};
const RFC_9110_10_1_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4",
    note: "The transfer-coding grammar the members are parsed with, including the quoted-string a parameter may carry",
};

impl Rule for TransferEncodingChunkedFinal {
    fn id(&self) -> &'static str {
        "transfer_encoding_chunked_final"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Collect the coding names in wire order across every field line.
        //
        // `None` means the value could not be read as a list at all: quoting
        // that never closes leaves every later comma inside it, and an order
        // derived from members that cannot be delimited would be a guess.
        // Unlike the ordering questions below, that one has an owner --
        // `transfer_coding_registered` reports a malformed
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
                let val = crate::helpers::headers::field_line_as_written(hv);
                if !crate::helpers::list::quoting_is_balanced(&val) {
                    return None;
                }
                // Quote-aware: a comma inside a transfer-parameter's
                // quoted-string value is not a list separator.
                // cite(RFC 9110 § 10.1.4): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
                for part in crate::helpers::list::split_commas_respecting_quotes(&val) {
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
                    // all is `transfer_coding_registered`'s finding.
                    // The trim is `OWS` because that is the whitespace the
                    // production prints around the `;`. `str::trim` would take
                    // more, and on a value read one `char` per octet there is
                    // more to take: %xA0 arrives as U+00A0, which
                    // `char::is_whitespace` admits and no `token` does.
                    // cite(RFC 9110 § 10.1.4): "transfer-coding    = token *( OWS ";" OWS transfer-parameter )"
                    // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                    let name = crate::helpers::headers::trim_ows(part.split(';').next().unwrap());
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
                let val = crate::helpers::headers::field_line_as_written(hv);
                // Bound rather than returned directly: the iterator borrows
                // `val`, and as a tail expression it outlives it. Not a style
                // choice -- inlining it does not compile.
                let found = crate::helpers::list::list_members(&val)
                    .any(|opt| opt.eq_ignore_ascii_case("close"));
                found
            })
        };

        let check = |headers: &hyper::HeaderMap, is_request: bool| -> Option<Violation> {
            let codings = collect(headers)?;

            if codings.is_empty() {
                return None;
            }

            // This sentence was cited on the collection loop from the day the
            // rule was written, and nothing implemented it. `chunked, chunked`
            // did produce a finding -- the position check below sees the
            // *first* one is not last -- but it said "chunked must be the final
            // coding" about a value whose final coding is chunked. The right
            // answer for the wrong reason, and unreadable to anyone trying to
            // fix it. Counted here, ahead of the position check, so the more
            // specific defect wins -- and ahead of the response's close
            // exemption, because this sentence offers no alternative. Nothing
            // in § 6.1 lets a closed connection excuse chunking twice.
            // cite(RFC 9112 § 6.1): "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed)."
            let chunked_count = codings.iter().filter(|c| *c == "chunked").count();
            if chunked_count > 1 {
                return Some(self.cited(
                    &RFC_9112_6_1,
                    ctx.severity,
                    format!(
                        "The chunked transfer coding must not be applied more than once: \
                             codings found '{}'",
                        codings.join(", ")
                    ),
                ));
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
            //
            // It guards only what follows. The duplication MUST NOT above has
            // no second alternative, and an earlier draft of this exemption sat
            // in front of it -- so a response could chunk twice and be excused
            // by announcing a close.
            // cite(RFC 9112 § 9.6): "A sender SHOULD send a Connection header field (Section 7.6.1 of [HTTP]) containing the "close" connection option when it intends to close a connection."
            if !is_request && announces_close(headers) {
                return None;
            }

            // If 'chunked' appears anywhere other than the final coding it's a violation
            if let Some(pos) = codings.iter().position(|c| c == "chunked") {
                if pos != codings.len() - 1 {
                    return Some(self.violation(ctx.severity, format!(
                            "Transfer-Encoding 'chunked' must be the final coding: codings found '{}'",
                            codings.join(", ")
                        )));
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
                return Some(self.cited(
                    &RFC_9112_6_1,
                    ctx.severity,
                    format!(
                        "A request that applies any transfer coding other than chunked must apply \
                             chunked as the final coding: codings found '{}'",
                        codings.join(", ")
                    ),
                ));
            }

            None
        };

        // Two messages, two findings. `check` answers for one message and
        // deliberately answers once — the three requirements are ordered so
        // the most specific one wins for a single coding sequence — but the
        // request's sequence and the response's are separate sequences
        // framing separate bodies. Reporting only the first meant a request
        // that applied a coding and never framed the result concealed a
        // response that chunked twice.
        let mut out = Vec::new();
        out.extend(check(&tx.request.headers, true));

        if let Some(resp) = &tx.response {
            // All three of § 6.1's requirements speak of a coding *applied to*
            // content or to a message body. In these two responses there is no
            // body for one to have been applied to, and the field means
            // something else entirely -- what the origin would have done for an
            // unconditional GET. Judging the sequence for how it frames a body
            // that does not exist would report an advisory value for failing at
            // a job it was never doing.
            // cite(RFC 9112 § 6.1): "Transfer-Encoding MAY be sent in a response to a HEAD request or in a 304 (Not Modified) response (Section 15.4.5 of [HTTP]) to a GET request, neither of which includes a message body, to indicate that the origin server would have applied a transfer coding to the message body if the request had been an unconditional GET."
            let bodiless = tx.request.method.eq_ignore_ascii_case("HEAD") || resp.status == 304;
            if !bodiless {
                out.extend(check(&resp.headers, false));
            }
        }

        out
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Transfer-Encoding Chunked Final")
    }

    fn description(&self) -> &'static str {
        "Enforces RFC 9112 §6.1's requirements on the sequence of transfer codings: `chunked` may be applied at most once, and when any other coding is applied `chunked` must come last. Codings are read in wire order across every `Transfer-Encoding` field line.\n\n**Three findings, three sentences.**\n\n- *\"A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).\"* — `chunked, chunked` is reported as duplication, not as a position problem.\n- *\"If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed.\"* — this is unconditional, so a request reading `Transfer-Encoding: gzip` is reported: it applies a coding and never frames the result.\n- *\"If any transfer coding other than chunked is applied to a response's content, the sender MUST either apply chunked as the final transfer coding or terminate the message by closing the connection.\"* — a **response** therefore has a second way to comply.\n\n**The response exemption, and what it rests on.** A transaction records no connection teardown, so the second alternative is read from `Connection: close`. RFC 9112 §9.6 makes announcing a close a **SHOULD**, not a MUST — so a response that closes silently is still reported here, and that is a known false positive rather than an oversight. It is also, in that state, disregarding §9.6. Narrowing further would mean giving up the response side entirely.\n\n**A response with no body is not judged.** §6.1 permits `Transfer-Encoding` on a response to `HEAD` and on a `304 (Not Modified)`, \"neither of which includes a message body\", where it indicates what the origin *would have* applied to an unconditional `GET`. All three requirements above speak of a coding applied to content, so none of them engage. The *request's* own field is judged as usual, whatever its method.\n\n**§7.1 does not say `chunked` must be last.** It defines the chunked coding — its grammar, its role in framing, and (at the end) that it takes no parameters. This rule's specifications used to cite §7.1 for the ordering requirement, which lives in §6.1.\n\n**Parsing.** Members are split on commas outside quoted-strings, the coding *name* is taken from in front of any parameters (so `chunked;ext=1` is still `chunked`), names are folded case-insensitively per §7, and values are decoded from raw octets — dropping a field line here would not merely lose a finding, it would silently reorder the sequence being judged. A value whose quoting never closes is declined, because its members cannot be delimited; `transfer_coding_registered` is the rule that reports it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9112_6_1, RFC_9112_9_6, RFC_9112_7_1, RFC_9110_10_1_4]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            // These were not HTTP messages. One jammed two field lines together
            // with a blank line between them and no start-line; the other
            // carried `#` comments, which no HTTP message has. `gendocs`
            // published both.
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: gzip, chunked\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(response closes the connection instead of chunking)"),
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: gzip\nConnection: close\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(request applies gzip and never frames the result)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: gzip\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(nothing may follow chunked)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked, gzip\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(chunking an already chunked message)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked, chunked\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &TransferEncodingChunkedFinal;

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
        let rule = TransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction();

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", value)],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "chunked",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates. The examples this replaces were
    /// not HTTP messages at all -- no start-line, `#` comments, two field lines
    /// separated by a blank one -- and nothing had ever tried to parse them.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = TransferEncodingChunkedFinal;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 3] = [
            ("gzip", "must apply chunked as the final coding"),
            ("chunked, gzip", "must be the final coding"),
            ("chunked, chunked", "must not be applied more than once"),
        ];

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("empty snippet");
            let is_response = start.starts_with("HTTP/");
            let pairs: Vec<(&str, &str)> = lines
                .take_while(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let te = pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("example has no Transfer-Encoding: {:?}", ex.snippet));

            let mut tx = if is_response {
                crate::test_helpers::make_test_transaction_with_response(200, &[])
            } else {
                crate::test_helpers::make_test_transaction()
            };
            let headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            if is_response {
                tx.response.as_mut().unwrap().headers = headers;
            } else {
                tx.request.headers = headers;
            }

            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {te:?}: {found:?}"
                ),
                Compliance::NonCompliant => {
                    let found = found
                        .unwrap_or_else(|| panic!("rule accepts its NonCompliant example {te:?}"));
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == te)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {te:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {te:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// Chunking an already chunked message is its own MUST NOT, and it was the
    /// one sentence this rule had cited since it was written. `chunked,
    /// chunked` used to be reported for `chunked` not being final, about a
    /// value whose final coding is chunked.
    #[rstest]
    #[case("chunked, chunked")]
    #[case("gzip, chunked, chunked")]
    #[case("chunked, gzip, chunked")]
    #[case("CHUNKED, chunked;ext=1")]
    fn chunked_applied_twice_is_reported_as_such(#[case] value: &str) {
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some_and(|v| v.message.contains("must not be applied more than once")),
            "{value:?} chunks an already chunked message"
        );
    }

    /// § 6.1 permits `Transfer-Encoding` on a HEAD response and on a 304, where
    /// it describes what the origin *would have* applied to a body that is not
    /// there. Every requirement here is about a coding applied to content, so
    /// none of them engage.
    #[rstest]
    #[case("HEAD", 200)]
    #[case("GET", 304)]
    fn a_response_with_no_body_is_not_judged_for_framing_one(
        #[case] method: &str,
        #[case] status: u16,
    ) {
        let rule = TransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            status,
            &[("transfer-encoding", "chunked, gzip")],
        );
        tx.request.method = method.to_string();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{method} -> {status}: {v:?}");
    }

    /// The exemption is the *response's*. A HEAD request that itself carries a
    /// body-framing coding is judged like any other request.
    #[test]
    fn a_head_request_is_still_judged_on_its_own_field() {
        let rule = TransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "gzip",
        )]);
        tx.request.method = "HEAD".to_string();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    /// The duplication MUST NOT has no second alternative, so the response's
    /// close exemption must not reach it. It briefly did.
    #[test]
    fn announcing_close_does_not_excuse_chunking_twice() {
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("transfer-encoding", "chunked, chunked"),
                ("connection", "close"),
            ],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some_and(|v| v.message.contains("must not be applied more than once")),
            "closing the connection is not one of this sentence's alternatives"
        );
    }

    /// Spread across field lines, which is the same message.
    #[test]
    fn chunked_twice_across_field_lines_is_reported() {
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some_and(|v| v.message.contains("must not be applied more than once")));
    }

    /// A response has a second way to satisfy § 6.1, and announcing the close
    /// is how it says so. Reporting it anyway was a false statement about a
    /// conforming message.
    #[rstest]
    #[case("chunked, gzip")]
    #[case("gzip")]
    fn a_response_that_announces_close_is_not_reported(#[case] te: &str) {
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", te), ("connection", "close")],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{te:?} with Connection: close: {v:?}");
    }

    /// `a_response_that_announces_close_is_not_reported` with the exemption
    /// spelled in an octet that is not a `tchar`. `connection-option = token`,
    /// so `close<%xA0>` is not the `close` option and the response has said
    /// nothing — the value is read with `from_utf8_lossy` and the pair arrives as
    /// one `char` `str::trim` calls whitespace, so the list walk used to hand
    /// back `close` and excuse the message.
    ///
    /// The same octet on the coding itself is the other half: the name in front
    /// of the `;` is `OWS`-trimmed now, so a request whose only coding is
    /// `chunked<%xA0>` has applied something that is not `chunked` and never
    /// framed the result. Both used to read as the bare token.
    #[test]
    fn an_obs_text_octet_is_not_whitespace_in_the_connection_option() {
        let rule = TransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[
                ("transfer-encoding", b"chunked, gzip".as_slice()),
                ("connection", b"close\xA0".as_slice()),
            ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.as_ref()
                .is_some_and(|v| v.message.contains("final coding")),
            "{v:?}"
        );
    }

    #[test]
    fn an_obs_text_octet_is_not_whitespace_in_the_coding_name() {
        let rule = TransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_octet_pairs(&[(
            "transfer-encoding",
            b"chunked\xA0".as_slice(),
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.as_ref()
                .is_some_and(|v| v.message.contains("must apply chunked as the final coding")),
            "{v:?}"
        );
    }

    /// The option is a token in a list and is matched as one, not by substring.
    #[rstest]
    #[case("keep-alive, close", true)]
    #[case("CLOSE", true)]
    #[case("keep-alive", false)]
    #[case("closed", false)]
    fn the_close_option_is_matched_as_a_list_token(#[case] connection: &str, #[case] exempt: bool) {
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("transfer-encoding", "chunked, gzip"),
                ("connection", connection),
            ],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "gzip"),
            ("connection", "close"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "the request MUST is unconditional");
    }

    #[test]
    fn multiple_header_fields_ordering_is_preserved() -> anyhow::Result<()> {
        let rule = TransferEncodingChunkedFinal;

        // Two header fields: first 'chunked', second 'gzip' -> should violate
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "gzip"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
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

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "gzip;ext=\"a,b\", chunked",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = TransferEncodingChunkedFinal;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            "chunked;ext=\"a, gzip",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// One coding sequence still gets one finding — the three requirements are
    /// ordered so the most specific wins — but the request's sequence and the
    /// response's are two sequences framing two bodies, and each answers for
    /// itself. The request here never frames its content; the response chunks
    /// twice. Reporting only the first hid the second.
    #[test]
    fn each_side_of_the_exchange_is_its_own_finding() {
        let rule = TransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", "chunked, chunked")],
        );
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "gzip")]);

        let all = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(all[0].message.contains("must apply"), "{}", all[0].message);
        assert!(
            all[1].message.contains("more than once"),
            "{}",
            all[1].message
        );
    }

    #[test]
    fn scope_is_both() {
        let rule = TransferEncodingChunkedFinal;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
