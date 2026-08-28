// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContentEncodingAndTypeConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4",
    note: "`Content-Encoding = #content-coding` — the list the member checks walk. Note it does not forbid repeating a coding, so the duplicate check is this rule's judgement",
};
const RFC_9110_15_4_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
    note: "Why a 304 should not carry Content-Encoding: a sender SHOULD NOT include representation metadata beyond the listed fields. (This reference previously pointed at §8.3, which is Content-Type, not message-body rules.) The 1xx and 204 cases have no such sentence and are inferred",
};

impl Rule for ContentEncodingAndTypeConsistent {
    fn id(&self) -> &'static str {
        "content_encoding_and_type_consistent"
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
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Helper to validate a Content-Encoding-like header value (comma-separated members).
            // This helper validates members in `val` and updates `seen` with found codings so duplicates
            // across multiple header fields can be detected when `seen` is shared between calls.
            let check_encoding_header = |hdr_name: &str,
                                         val: &str,
                                         seen: &mut std::collections::HashSet<String>|
             -> Option<Violation> {
                // cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
                for part in crate::helpers::headers::list_members(val) {
                    // Strip parameters (not expected for Content-Encoding but be forgiving)
                    let token = part.split(';').next().unwrap().trim();
                    if token.is_empty() {
                        return Some(self.violation(
                            ctx.severity,
                            format!("{} header contains empty member", hdr_name),
                        ));
                    }
                    if token == "*" && hdr_name.eq_ignore_ascii_case("Content-Encoding") {
                        return Some(self.violation(
                            ctx.severity,
                            format!("Wildcard '*' is not valid in {} header", hdr_name),
                        ));
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                        return Some(self.violation(
                            ctx.severity,
                            format!("Invalid token '{}' in {} header", c, hdr_name),
                        ));
                    }
                    // Repeating a coding is not forbidden anywhere: §8.4 has the sender list
                    // the codings "in the order in which they were applied", which makes
                    // `gzip, gzip` a well-formed way to say gzip was applied twice. Flagging
                    // it is this rule's judgement that a repeat is far more often a
                    // configuration accident (two layers each adding the header) than a
                    // deliberate double-encoding. Uncited, since no sentence licenses it.
                    let key = token.to_ascii_lowercase();
                    if !seen.insert(key.clone()) {
                        return Some(self.violation(
                            ctx.severity,
                            format!("Duplicate content-coding '{}' in {} header", key, hdr_name),
                        ));
                    }
                }
                None
            };

            // Check request Content-Encoding header(s) (track across multiple header fields)
            {
                let mut seen = std::collections::HashSet::new();
                for hv in tx.request.headers.get_all("content-encoding").iter() {
                    let Ok(val) = hv.to_str() else {
                        return Some(self.violation(
                            ctx.severity,
                            "Content-Encoding header value is not valid UTF-8".into(),
                        ));
                    };
                    if let Some(v) = check_encoding_header("Content-Encoding", val, &mut seen) {
                        return Some(v);
                    }
                }
            }

            // Check response Content-Encoding header(s)
            if let Some(resp) = &tx.response {
                // No-body statuses should not carry Content-Encoding
                let status = resp.status;
                // These three statuses reach the same verdict by different routes, and only
                // one of them is a stated requirement.
                //
                // 304 is the grounded case: Content-Encoding is representation metadata,
                // it is not among the fields a 304 is told to send, and it does not guide
                // cache updates — so the sentence below covers it directly (a SHOULD NOT,
                // which is why the message says "should not").
                // cite(RFC 9110 § 15.4.5): "a sender SHOULD NOT generate representation metadata other than the above listed fields unless said metadata exists for the purpose of guiding cache updates"
                //
                // 1xx and 204 are the linter's inference: those responses carry no content,
                // so a coding describing how the content was encoded has nothing to
                // describe. No sentence says this, and for 204 the spec arguably leans the
                // other way — §15.3.5 has metadata "refer to the target resource and its
                // selected representation", which would make representation metadata
                // meaningful even with no content to send. Kept because a Content-Encoding
                // on a bodyless response is far more often a misconfiguration than a
                // deliberate description of a representation the client is not receiving;
                // recorded as the possible false positive it is.
                let is_no_body_status =
                    (100..200).contains(&status) || status == 204 || status == 304;
                if is_no_body_status && resp.headers.contains_key("content-encoding") {
                    return Some(self.cited(&RFC_9110_15_4_5, ctx.severity, format!(
                            "Response {} carries no content, so it should not send Content-Encoding",
                            status
                        )));
                }

                let mut seen = std::collections::HashSet::new();
                for hv in resp.headers.get_all("content-encoding").iter() {
                    let Ok(val) = hv.to_str() else {
                        return Some(self.violation(
                            ctx.severity,
                            "Content-Encoding header value is not valid UTF-8".into(),
                        ));
                    };
                    if let Some(v) = check_encoding_header("Content-Encoding", val, &mut seen) {
                        return Some(v);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate `Content-Encoding` header members for common correctness issues: members must be valid `token`s, a wildcard `*` is rejected (it belongs to `Accept-Encoding`), and a coding repeated within the field is flagged.\n\nResponses that carry no content (1xx, 204, 304) are flagged for sending `Content-Encoding` at all. For 304 this follows RFC 9110 §15.4.5, which tells a sender not to include representation metadata beyond a listed set; for 1xx and 204 it is this rule's inference that a coding describing absent content is a misconfiguration.\n\nRepeating a coding is likewise a judgement call rather than a conformance failure — `gzip, gzip` legitimately expresses gzip applied twice — but in practice it usually means two layers each added the header.\n\n**Note:** despite the rule's name, no `Content-Type` consistency check is performed; the rule inspects `Content-Encoding` only."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_4, RFC_9110_15_4_5]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip, br\nContent-Type: application/json; charset=utf-8\n\n...compressed JSON body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(duplicate coding)"),
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip, gzip\nContent-Type: application/json\n\n...compressed JSON body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(Content-Encoding on no-body response)"),
                snippet: "HTTP/1.1 204 No Content\nContent-Encoding: gzip",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentEncodingAndTypeConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("gzip"), 200, false)]
    #[case(Some("gzip, br"), 200, false)]
    #[case(Some("gzip, gzip"), 200, true)]
    #[case(Some("x@bad"), 200, true)]
    #[case(Some("gzip"), 204, true)]
    #[case(Some("gzip, "), 200, false)]
    #[case(None, 200, false)]
    fn response_cases(
        #[case] ce: Option<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("gzip, gzip"), true)]
    #[case(Some("x@bad"), true)]
    #[case(Some("gzip"), false)]
    #[case(None, false)]
    fn request_cases(
        #[case] ce: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ce {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_value_reports_violation() {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),

            body_length: None,
            trailers: None,
        });
        tx.response.as_mut().unwrap().headers.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_eq!(
            v.message,
            "Content-Encoding header value is not valid UTF-8"
        );
    }
    #[test]
    fn request_trailing_comma_accepted() {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip, ")]);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
    #[test]
    fn content_encoding_wildcard_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        // request header with '*'
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v1.is_some());

        // response header with '*'
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_some());

        Ok(())
    }

    #[test]
    fn duplicate_across_multiple_header_fields_reports_violation_response() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Two header fields both mentioning 'gzip' should be treated as duplicate
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn duplicate_across_multiple_header_fields_reports_violation_request() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_and_type_consistent",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentEncodingAndTypeConsistent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn empty_list_member_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // include a semicolon-only member (";") between commas which will leave a non-empty
        // part but its token before the ';' is empty -> triggers the rule
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip,;,br")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_non_utf8_value_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        tx.request
            .headers
            .append("content-encoding", HeaderValue::from_bytes(&[0xff])?);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(
            v.message,
            "Content-Encoding header value is not valid UTF-8"
        );
        Ok(())
    }

    #[test]
    fn response_no_body_status_with_encoding_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(100, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("should not send Content-Encoding"));
        Ok(())
    }
}
