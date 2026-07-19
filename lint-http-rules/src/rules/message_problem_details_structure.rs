// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageProblemDetailsStructure;

impl Rule for MessageProblemDetailsStructure {
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

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
                    // If the transaction contains captured body bytes, inspect them
                    // conservatively. Skip byte inspection when the captured body is a
                    // truncated prefix (streaming): a truncated JSON object would
                    // mis-parse. The length-based checks below use the real
                    // `body_length`, so coverage degrades gracefully.
                    if let Some(b) = tx
                        .response_body
                        .as_ref()
                        .filter(|_| !tx.response_body_over_limit)
                    {
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

    fn description(&self) -> &'static str {
        "When a server expresses an error using the Problem Details media type (`application/problem+json`), the response body SHOULD be a JSON object carrying problem details (see RFC 7807). This rule performs conservative, syntactic checks on such responses: it verifies the response is an error (4xx/5xx) and that `application/problem+json` responses include a non-empty body. Captured bodies are available to rules in memory; the `captures_include_body` setting only controls whether bodies are persisted to the captures file. When body bytes are present, the rule will attempt to parse the body and ensure it is a non-empty JSON object. If body bytes are not present, the rule conservatively flags when a captured or indicated Content-Length of zero is present."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 7807",
            section: Some("3.1"),
            url: "https://www.rfc-editor.org/rfc/rfc7807.html#section-3.1",
            note: "Problem Details for HTTP APIs",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 400 Bad Request\nContent-Type: application/problem+json\nContent-Length: 123\n\n{\"type\":\"about:blank\",\"title\":\"Bad Request\",\"detail\":\"invalid input\"}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 500 Internal Server Error\nContent-Type: application/problem+json\nContent-Length: 0\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageProblemDetailsStructure;

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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });
        tx.response_body = Some(bytes::Bytes::from_static(b""));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{}"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{\"type\":\"x\"}"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn truncated_body_prefix_skips_byte_inspection() {
        // A truncated prefix of a problem+json body would mis-parse; the rule
        // must skip byte inspection and fall back to body_length (real size).
        let rule = MessageProblemDetailsStructure;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 500,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(4096),
            trailers: None,
        });
        // Prefix is a truncated (unparseable) JSON object.
        tx.response_body = Some(bytes::Bytes::from_static(b"{\"type\":\"abo"));
        tx.response_body_over_limit = true;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "truncated prefix must not be parsed as a full body"
        );
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
            trailers: None,
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"not json"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }
}
