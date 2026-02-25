// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageProblemDetailsStructure;

impl Rule for MessageProblemDetailsStructure {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_problem_details_structure"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Only consider responses that indicate an error or problem (4xx/5xx)
        if resp.status < 400 {
            return None;
        }

        // If Content-Type is application/problem+json, ensure a non-empty body is present
        if let Some(ct_str) = crate::helpers::headers::get_header_str(&resp.headers, "content-type")
        {
            if let Ok(parsed) = crate::helpers::headers::parse_media_type(ct_str) {
                let t = parsed.type_.to_ascii_lowercase();
                let sub = parsed.subtype.to_ascii_lowercase();

                if t == "application" && sub == "problem+json" {
                    // If the transaction contains captured body bytes, inspect them conservatively
                    if let Some(b) = &tx.response_body {
                        // Empty bytes -> violation
                        if b.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Problem Details response using 'application/problem+json' must include a non-empty JSON object body".into(),
                            });
                        }

                        // Try parsing JSON and ensure it's a non-empty object
                        if let Ok(serde_json::Value::Object(m)) =
                            serde_json::from_slice::<serde_json::Value>(b)
                        {
                            if m.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Problem Details response using 'application/problem+json' must include a non-empty JSON object body".into(),
                                });
                            } else {
                                return None;
                            }
                        } else {
                            // Unparseable JSON or not an object -> violation
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Problem Details response using 'application/problem+json' must include a non-empty JSON object body".into(),
                            });
                        }
                    }

                    // If we have a captured body length of exactly zero -> violation
                    if let Some(len) = resp.body_length {
                        if len == 0 {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Problem Details response using 'application/problem+json' must include a non-empty JSON object body".into(),
                            });
                        }
                        // non-zero length -> no violation (we cannot inspect content here)
                        return None;
                    }

                    // If Content-Length header explicitly zero -> violation
                    if let Some(cl) =
                        crate::helpers::headers::get_header_str(&resp.headers, "content-length")
                    {
                        if let Ok(v) = cl.trim().parse::<u64>() {
                            if v == 0 {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Problem Details response using 'application/problem+json' must include a non-empty JSON object body".into(),
                                });
                            } else {
                                return None;
                            }
                        }
                    }

                    // We don't have captured body length nor Content-Length -> be conservative and do not flag
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(400, Some(("application/problem+json", "content-length", "0")), true)]
    #[case(500, Some(("application/problem+json", "content-length", "10")), false)]
    #[case(404, Some(("application/problem+json", "content-length", "0")), true)]
    #[case(400, Some(("application/problem+json", "content-length", "")), false)] // malformed cl -> ignore
    #[case(400, Some(("application/problem+json", "content-length", " 0 ")), true)]
    fn problem_details_content_length_cases(
        #[case] status: u16,
        #[case] hdr: Option<(&str, &str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = Vec::new();
        if let Some((ct, cl_name, cl_val)) = hdr {
            headers.push(("content-type", ct));
            if !cl_val.is_empty() {
                headers.push((cl_name, cl_val));
            }
        }

        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&headers),
            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for hdr={:?}", hdr);
            assert!(v.unwrap().message.contains("Problem Details response"));
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for hdr={:?}: {:?}",
                hdr,
                v
            );
        }
    }

    #[test]
    fn body_length_zero_reports_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(0),
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Problem Details response"));
    }

    #[test]
    fn non_zero_body_length_no_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 400,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(10),
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_error_status_ignored() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(0),
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn body_bytes_empty_reports_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(0),
        });
        tx.response_body = Some(bytes::Bytes::from_static(b""));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn body_bytes_empty_object_reports_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(2),
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{}"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn body_bytes_non_empty_object_no_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(20),
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{\"type\":\"x\"}"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn body_bytes_non_json_reports_violation() {
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(7),
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"not json"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }
}
