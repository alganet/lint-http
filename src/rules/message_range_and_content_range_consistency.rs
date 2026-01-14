// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRangeAndContentRangeConsistency;

impl Rule for MessageRangeAndContentRangeConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_range_and_content_range_consistency"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let status = resp.status;
        let has_range_request = tx.request.headers.get("range").is_some();

        // 206 Partial Content rules
        if status == 206 {
            // 206 MUST include a valid Content-Range
            let cr = crate::helpers::headers::get_header_str(&resp.headers, "content-range");
            if cr.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "206 Partial Content response missing Content-Range header".into(),
                });
            }
            let cr = cr.unwrap();
            match crate::helpers::content_range::parse_content_range(cr) {
                Ok(crate::helpers::content_range::ContentRange::Satisfied {
                    first, last, ..
                }) => {
                    // If no Range was present in the request, 206 is unexpected
                    if !has_range_request {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "206 Partial Content response received but request did not include a Range header".into(),
                        });
                    }

                    // If Content-Length is present, it must equal last-first+1
                    if let Some(cl) =
                        crate::helpers::headers::get_header_str(&resp.headers, "content-length")
                    {
                        if let Ok(cl_v) = cl.trim().parse::<u128>() {
                            let expected = (last - first) + 1;
                            if cl_v != expected {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Content-Length ({}) does not match Content-Range length ({})", cl_v, expected),
                                });
                            }
                        } else {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid Content-Length value: {}", cl),
                            });
                        }
                    }
                }
                Ok(crate::helpers::content_range::ContentRange::Unsatisfiable { .. }) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "206 response must not use '*' byte-range-resp-spec (use 416 for unsatisfiable ranges)".into(),
                    });
                }
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Range header '{}': {}", cr, e),
                    });
                }
            }
        }

        // 416 Range Not Satisfiable rules
        if status == 416 {
            // 416 MUST include a Content-Range with "*" response and instance-length
            let cr = crate::helpers::headers::get_header_str(&resp.headers, "content-range");
            if cr.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "416 Range Not Satisfiable response missing Content-Range header"
                        .into(),
                });
            }
            let cr = cr.unwrap();
            match crate::helpers::content_range::parse_content_range(cr) {
                Ok(crate::helpers::content_range::ContentRange::Unsatisfiable { .. }) => {
                    // ok
                }
                Ok(crate::helpers::content_range::ContentRange::Satisfied { .. }) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "416 response must use '*' byte-range-resp-spec in Content-Range"
                            .into(),
                    });
                }
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Range header '{}': {}", cr, e),
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
    use rstest::rstest;

    #[rstest]
    fn valid_206_with_matching_length() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-range", "bytes 0-499/1234"),
                ("content-length", "500"),
            ],
        );
        // add Range header to request to make 206 valid
        let mut tx = tx;
        tx.request
            .headers
            .insert("range", "bytes=0-499".parse().unwrap());

        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn test_206_missing_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing Content-Range"));
    }

    #[rstest]
    fn test_206_with_invalid_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 5-3/10")],
        );
        tx.request
            .headers
            .insert("range", "bytes=5-3".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[rstest]
    fn test_206_without_range_in_request_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 0-1/10")],
        );
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("request did not include a Range"));
    }

    #[rstest]
    fn content_length_mismatch_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-range", "bytes 0-499/1234"),
                ("content-length", "400"),
            ],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-499".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[rstest]
    fn test_416_requires_unsatisfiable_content_range() {
        let tx_ok = crate::test_helpers::make_test_transaction_with_response(
            416,
            &[("content-range", "bytes */1234")],
        );
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx_ok, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());

        let tx_bad = crate::test_helpers::make_test_transaction_with_response(
            416,
            &[("content-range", "bytes 0-0/1234")],
        );
        let v2 =
            rule.check_transaction(&tx_bad, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());

        let tx_missing = crate::test_helpers::make_test_transaction_with_response(416, &[]);
        let v3 = rule.check_transaction(
            &tx_missing,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v3.is_some());
    }

    #[rstest]
    fn test_206_with_unsatisfiable_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes */1234")],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not use '*'"));
    }

    #[rstest]
    fn test_206_with_non_numeric_content_length_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 0-1/10"), ("content-length", "abc")],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Content-Length"));
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageRangeAndContentRangeConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_range_and_content_range_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
