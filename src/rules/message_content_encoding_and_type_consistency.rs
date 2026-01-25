// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentEncodingAndTypeConsistency;

impl Rule for MessageContentEncodingAndTypeConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_encoding_and_type_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to validate a Content-Encoding-like header value (comma-separated members).
        // This helper validates members in `val` and updates `seen` with found codings so duplicates
        // across multiple header fields can be detected when `seen` is shared between calls.
        let check_encoding_header = |hdr_name: &str,
                                     val: &str,
                                     seen: &mut std::collections::HashSet<String>|
         -> Option<Violation> {
            for part in crate::helpers::headers::parse_list_header(val) {
                // Strip parameters (not expected for Content-Encoding but be forgiving)
                let token = part.split(';').next().unwrap().trim();
                if token.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} header contains empty member", hdr_name),
                    });
                }
                if token == "*" && hdr_name.eq_ignore_ascii_case("Content-Encoding") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Wildcard '*' is not valid in {} header", hdr_name),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in {} header", c, hdr_name),
                    });
                }
                let key = token.to_ascii_lowercase();
                if !seen.insert(key.clone()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Duplicate content-coding '{}' in {} header",
                            key, hdr_name
                        ),
                    });
                }
            }
            None
        };

        // Check request Content-Encoding header(s) (track across multiple header fields)
        {
            let mut seen = std::collections::HashSet::new();
            for hv in tx.request.headers.get_all("content-encoding").iter() {
                if let Ok(val) = hv.to_str() {
                    if let Some(v) = check_encoding_header("Content-Encoding", val, &mut seen) {
                        return Some(v);
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Encoding header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        // Check response Content-Encoding header(s)
        if let Some(resp) = &tx.response {
            // No-body statuses should not carry Content-Encoding
            let status = resp.status;
            let is_no_body_status = (100..200).contains(&status) || status == 204 || status == 304;
            if is_no_body_status && resp.headers.contains_key("content-encoding") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Response {} must not have a Content-Encoding header (no message body)",
                        status
                    ),
                });
            }

            let mut seen = std::collections::HashSet::new();
            for hv in resp.headers.get_all("content-encoding").iter() {
                if let Ok(val) = hv.to_str() {
                    if let Some(v) = check_encoding_header("Content-Encoding", val, &mut seen) {
                        return Some(v);
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Encoding header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        None
    }
}

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
        let rule = MessageContentEncodingAndTypeConsistency;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
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
        let rule = MessageContentEncodingAndTypeConsistency;

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ce {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_value_reports_violation() {
        let rule = MessageContentEncodingAndTypeConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),

            body_length: None,
        });
        tx.response.as_mut().unwrap().headers.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );

        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_eq!(
            v.message,
            "Content-Encoding header value is not valid UTF-8"
        );
    }

    #[test]
    fn content_encoding_wildcard_reports_violation() -> anyhow::Result<()> {
        let rule = MessageContentEncodingAndTypeConsistency;

        // request header with '*'
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v1 = rule.check_transaction(&tx1, None, &crate::test_helpers::make_test_rule_config());
        assert!(v1.is_some());

        // response header with '*'
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());

        Ok(())
    }

    #[test]
    fn duplicate_across_multiple_header_fields_reports_violation_response() -> anyhow::Result<()> {
        let rule = MessageContentEncodingAndTypeConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Two header fields both mentioning 'gzip' should be treated as duplicate
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn duplicate_across_multiple_header_fields_reports_violation_request() -> anyhow::Result<()> {
        let rule = MessageContentEncodingAndTypeConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_and_type_consistency",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentEncodingAndTypeConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
