// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate Date, Last-Modified, If-Modified-Since and Sunset header consistency and formats.
pub struct MessageDateAndTimeHeadersConsistency;

impl Rule for MessageDateAndTimeHeadersConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_date_and_time_headers_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        use chrono::Duration;

        // Tolerate some small clock skew when comparing dates
        const ALLOWED_SKEW_SECS: i64 = 60;
        let skew = Duration::seconds(ALLOWED_SKEW_SECS);

        // Check Date header (request or response)
        if let Some(hv) = tx.request.headers.get_all("date").iter().next() {
            if let Ok(s) = hv.to_str() {
                if crate::http_date::parse_http_date_to_datetime(s).is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Date header is not a valid IMF-fixdate (RFC 9110)".into(),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Date header contains non-UTF8 bytes and is invalid".into(),
                });
            }
        }

        if let Some(resp) = &tx.response {
            // Response Date check
            if let Some(hv) = resp.headers.get_all("date").iter().next() {
                if let Ok(s) = hv.to_str() {
                    if crate::http_date::parse_http_date_to_datetime(s).is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Date header is not a valid IMF-fixdate (RFC 9110)".into(),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Date header contains non-UTF8 bytes and is invalid".into(),
                    });
                }
            }

            // If both Date and Last-Modified present and parseable, ensure Last-Modified is not in the future relative to Date
            if let Some(date_str) = crate::helpers::headers::get_header_str(&resp.headers, "date") {
                if let Ok(date_dt) = crate::http_date::parse_http_date_to_datetime(date_str) {
                    if let Some(lm_str_raw) = resp.headers.get_all("last-modified").iter().next() {
                        // handle non-utf8
                        match lm_str_raw.to_str() {
                            Ok(lm_str) => {
                                match crate::http_date::parse_http_date_to_datetime(lm_str) {
                                    Ok(lm_dt) => {
                                        if lm_dt > date_dt + skew {
                                            return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Last-Modified '{}' is later than Date '{}'; Last-Modified must not be in the future relative to Date",
                                                lm_str, date_str
                                            ),
                                        });
                                        }
                                    }
                                    Err(_) => {
                                        // Let dedicated Last-Modified format rule report invalid date; avoid duplicate
                                    }
                                }
                            }
                            Err(_) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Last-Modified header contains non-UTF8 bytes and is invalid".into(),
                                });
                            }
                        }
                    }

                    // Sunset header: must be a valid HTTP-date and should be in the future or at least not in the past relative to Date
                    for hv in resp.headers.get_all("sunset").iter() {
                        match hv.to_str() {
                            Ok(s) => {
                                match crate::http_date::parse_http_date_to_datetime(s) {
                                    Ok(sunset_dt) => {
                                        if sunset_dt <= date_dt - skew {
                                            return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Sunset header '{}' is before or equal to Date '{}'; Sunset should indicate a future shutdown date",
                                                s, date_str
                                            ),
                                        });
                                        }
                                    }
                                    Err(_) => {
                                        return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: "Sunset header is not a valid IMF-fixdate (RFC 8594)".into(),
                                    });
                                    }
                                }
                            }
                            Err(_) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Sunset header contains non-UTF8 bytes and is invalid"
                                        .into(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Request-level If-Modified-Since: if Date header present in request, ensure If-Modified-Since not in the future relative to Date
        if let Some(ifms_hv) = tx
            .request
            .headers
            .get_all("if-modified-since")
            .iter()
            .next()
        {
            match ifms_hv.to_str() {
                Ok(ifms_str) => match crate::http_date::parse_http_date_to_datetime(ifms_str) {
                    Ok(ifms_dt) => {
                        if let Some(date_str) =
                            crate::helpers::headers::get_header_str(&tx.request.headers, "date")
                        {
                            if let Ok(date_dt) =
                                crate::http_date::parse_http_date_to_datetime(date_str)
                            {
                                if ifms_dt > date_dt + skew {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "If-Modified-Since '{}' is later than Date '{}'; conditional requests should not use a future date",
                                            ifms_str, date_str
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // If-Modified-Since format is validated by dedicated rule; avoid duplicate reporting
                    }
                },
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-Modified-Since header contains non-UTF8 bytes and is invalid"
                            .into(),
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
    #[case(Some(vec![("date", "not-a-date")] ), true)]
    #[case(Some(vec![("date", "Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(None, false)]
    fn date_format_cases(
        #[case] headers: Option<Vec<(&str, &str)>>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();

        if let Some(h) = headers {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&h);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Date header is not a valid IMF-fixdate") || m.contains("non-UTF8"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn last_modified_after_date_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("last-modified", "Wed, 21 Oct 2015 07:30:00 GMT"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Last-Modified"));
        Ok(())
    }

    #[test]
    fn sunset_before_date_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("sunset", "Wed, 21 Oct 2015 07:27:00 GMT"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset"));
        Ok(())
    }

    #[test]
    fn if_modified_since_after_date_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("if-modified-since", "Wed, 21 Oct 2015 07:30:00 GMT"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("If-Modified-Since"));
        Ok(())
    }

    #[test]
    fn non_utf8_date_header_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("date", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn sunset_invalid_format_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("sunset", "not-a-date"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset header is not a valid IMF-fixdate"));
        Ok(())
    }

    #[test]
    fn last_modified_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "date",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("last-modified", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Last-Modified header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn if_modified_since_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("if-modified-since", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("If-Modified-Since header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn response_date_invalid_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("date", "not-a-date")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Date header is not a valid IMF-fixdate"));
        Ok(())
    }

    #[test]
    fn sunset_without_date_is_ignored() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "sunset",
            "Tue, 01 Jan 2030 00:00:00 GMT",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_date_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("date", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Date header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn last_modified_invalid_format_is_ignored() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("last-modified", "not-a-date"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        // Parse error for Last-Modified should be ignored by this rule (other rule will report)
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn if_modified_since_invalid_format_is_ignored() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("if-modified-since", "not-a-date"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        // Parse error for If-Modified-Since should be ignored by this rule (other rule will report)
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn if_modified_since_without_date_is_ignored() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:30:00 GMT",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        // Without a Date header to compare against, the rule should not produce a violation
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn sunset_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDateAndTimeHeadersConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "date",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("sunset", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageDateAndTimeHeadersConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_date_and_time_headers_consistency");
        // Should validate and produce an engine without error
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
