// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCompressionAndTransferEncodingConsistency;

impl Rule for MessageCompressionAndTransferEncodingConsistency {
    fn id(&self) -> &'static str {
        "message_compression_and_transfer_encoding_consistency"
    }

    /// `Both`, because both fields are defined for both directions and the
    /// observation this rule makes is about two *layers*, not two roles. It was
    /// `Server`, which in this engine means "skip when there is no response" --
    /// so a request carrying the same coding in both fields was never examined
    /// at all.
    /// cite(RFC 9110 § 8.4): "An origin server MAY respond with a status code of 415 (Unsupported Media Type) if a representation in the request message has a content coding that is not acceptable."
    /// cite(RFC 9112 § 6.1): "If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed."
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

        // Both fields are lists whose members a sender may spread over several
        // field lines, and there the resemblance ends: their grammars differ in
        // a way that decides how each is split.
        //
        // Values are decoded from the raw octets rather than read through
        // `to_str`, which refuses everything outside visible US-ASCII and used
        // to drop the whole field line. Neither coding name can contain such an
        // octet -- both are `token` -- so one appearing where a name belongs
        // simply fails to match anything, which is the right outcome; dropping
        // the line instead hid every *other* name on it.
        let decode =
            |hv: &hyper::header::HeaderValue| String::from_utf8_lossy(hv.as_bytes()).into_owned();

        let check = |headers: &hyper::HeaderMap, side: &str| -> Option<Violation> {
            // `content-coding` is a bare `token` with no parameters, so every comma
            // is a separator and there is no quoting to respect.
            // cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
            // cite(RFC 9110 § 8.4.1): "content-coding   = token"
            let mut ce_set = std::collections::HashSet::new();
            for hv in headers.get_all("content-encoding").iter() {
                let s = decode(hv);
                for part in crate::helpers::headers::parse_list_header(&s) {
                    // Nothing in this field's grammar sits behind a `;`, so this
                    // strips something that cannot legally be there. It is kept as
                    // a deliberate tolerance: a sender writing `gzip;q=1.0` here
                    // has produced one malformed token, and reading the name out of
                    // it keeps this advisory useful on a value that
                    // `message_content_encoding_iana_registered` is already
                    // reporting as malformed. It cannot invent an overlap -- the
                    // text before the `;` is text the sender wrote.
                    // cite(RFC 9110 § 8.4.1): "All content codings are case-insensitive and ought to be registered within the "HTTP Content Coding Registry","
                    let token = part.split(';').next().unwrap().trim().to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    ce_set.insert(token);
                }
            }

            // `transfer-coding` does carry parameters, and a parameter value may be
            // a `quoted-string` holding a comma, so this split has to respect them.
            // cite(RFC 9110 § 10.1.4): "transfer-coding    = token *( OWS ";" OWS transfer-parameter )"
            // cite(RFC 9110 § 10.1.4): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
            let mut te_set = std::collections::HashSet::new();
            for hv in headers.get_all("transfer-encoding").iter() {
                let s = decode(hv);
                for part in crate::helpers::headers::split_commas_respecting_quotes(&s) {
                    // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
                    let token = part.split(';').next().unwrap().trim().to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    te_set.insert(token);
                }
            }

            // If either header is absent or no valid tokens present, nothing to check
            if ce_set.is_empty() || te_set.is_empty() {
                return None;
            }

            // Find overlapping tokens between Content-Encoding and Transfer-Encoding
            let mut overlap: Vec<String> = ce_set
                .intersection(&te_set)
                .map(|s| s.to_string())
                .collect();
            overlap.sort();

            if !overlap.is_empty() {
                return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Compression coding(s) '{}' appear in both Content-Encoding and Transfer-Encoding of the {}; the representation is coded once and then coded again in transit, which is decodable but almost never intended",
                    overlap.join(", "),
                    side
                ),
            });
            }

            None
        };

        if let Some(v) = check(&tx.request.headers, "request") {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers, "response") {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Responses that use representation compression (e.g., `Content-Encoding: gzip`) should not duplicate the same compression coding in `Transfer-Encoding`. `Content-Encoding` signals end-to-end transformations applied to the representation by the origin, while `Transfer-Encoding` describes hop-by-hop transport codings. The rule flags cases where the same compression coding appears in both headers which is likely unintended and confusing."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4",
                note: "Content Coding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
                note: "Transfer Codings and `Transfer-Encoding`",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip\nTransfer-Encoding: chunked\n\n<compressed-body-chunked>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(transfer-level gzip without Content-Encoding)"),
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: gzip, chunked\n\n<gzip-then-chunked-bytes>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(duplicate compression codings)"),
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip\nTransfer-Encoding: gzip, chunked\n\n<body>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageCompressionAndTransferEncodingConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_tx_with_headers(
        ce: Option<&str>,
        te: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }
        if let Some(v) = te {
            // Merge TE header without clobbering CE
            let mut hm = tx.response.as_mut().unwrap().headers.clone();
            hm.extend(crate::test_helpers::make_headers_from_pairs(&[(
                "transfer-encoding",
                v,
            )]));
            tx.response.as_mut().unwrap().headers = hm;
        }
        tx
    }

    #[rstest]
    // Added coverage for params, case-insensitive tokens, trailing commas
    #[case(Some("gzip"), Some("chunked, gzip"), true)]
    #[case(Some("gzip"), Some("chunked"), false)]
    #[case(Some("br, gzip"), Some("gzip, chunked"), true)]
    #[case(Some("gzip"), None, false)]
    #[case(None, Some("gzip"), false)]
    #[case(Some("gzip;q=1.0"), Some("gzip"), true)]
    #[case(Some("GZip"), Some("gzip"), true)]
    #[case(Some("gzip, "), Some("gzip"), true)]
    fn overlap_cases(
        #[case] ce: Option<&str>,
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx_with_headers(ce, te);
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for ce={:?} te={:?}",
                ce,
                te
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for ce={:?} te={:?}: {:?}",
                ce,
                te,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_detected() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Append multiple Content-Encoding fields
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        hm.append("content-encoding", HeaderValue::from_static("br"));
        hm.append("transfer-encoding", HeaderValue::from_static("br, chunked"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    /// An octet outside visible US-ASCII is not a `tchar`, so a name carrying
    /// one matches nothing -- which is the right answer on its own account.
    /// Dropping the whole line, as `to_str` used to make this rule do, also hid
    /// every other name on it.
    #[test]
    fn a_stray_octet_does_not_hide_the_rest_of_the_line() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "content-encoding",
            HeaderValue::from_bytes(b"\xff, gzip").unwrap(),
        );
        hm.append(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("gzip")),
            "the gzip after the stray octet went unread"
        );
    }

    /// The undecodable name on its own overlaps with nothing.
    #[test]
    fn a_name_that_is_only_a_stray_octet_matches_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        hm.append(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// A comma inside a transfer-parameter's quoted-string value is not a
    /// separator, so it must not manufacture a coding name that then appears to
    /// overlap. `Content-Encoding` needs no such care: its members are bare
    /// `token`s with no parameters and so no quoting.
    #[test]
    fn a_comma_inside_a_quoted_transfer_parameter_is_not_a_separator() {
        let tx = make_tx_with_headers(Some("br"), Some("chunked;ext=\"a,br,b\""));
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "the `br` is inside a parameter value: {v:?}");
    }

    #[test]
    fn overlapping_multiple_tokens_message_contains_both_sorted() {
        let tx = make_tx_with_headers(Some("gzip, br"), Some("br, gzip"));
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("br, gzip"));
    }

    /// `Both`, so that a request-only transaction is examined too. It was
    /// `Server`, which in this engine means the rule never ran without a
    /// response.
    #[test]
    fn scope_is_both() {
        let rule = MessageCompressionAndTransferEncodingConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// A request can apply a content coding to the body it sends and a transfer
    /// coding on top of it, which is the same observation on the same two
    /// layers. Nothing looked.
    #[test]
    fn a_request_with_the_same_coding_in_both_fields_is_reported() {
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("content-encoding", "gzip"),
            ("transfer-encoding", "gzip, chunked"),
        ]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("of the request")),
            "the request side was never examined"
        );
    }

    /// The two sides are reported separately, so a clean request does not
    /// suppress a response finding and the message says which is which.
    #[test]
    fn the_message_names_the_side_it_is_about() {
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let tx = make_tx_with_headers(Some("br"), Some("br, chunked"));
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some_and(|v| v.message.contains("of the response")));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        // Use the project test helper to enable the rule and validate full engine path
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        // When rule is enabled but missing required 'severity', validation should fail
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        // Remove severity key from the rule table
        if let Some(toml::Value::Table(table)) = cfg
            .rules
            .get_mut("message_compression_and_transfer_encoding_consistency")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
