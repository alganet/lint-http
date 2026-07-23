// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate Date, Last-Modified, If-Modified-Since and Sunset header consistency and formats.
pub struct MessageDateAndTimeHeadersConsistency;

impl Rule for MessageDateAndTimeHeadersConsistency {
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        use chrono::Duration;

        // Tolerate some small clock skew when comparing dates. 60s is a linter
        // heuristic — no spec licenses it; §8.8.2.1's "MUST NOT ... later than ...
        // Date" is strict, so this only makes the rule *more* lenient (recorded in
        // the audit ledger, not cited).
        const ALLOWED_SKEW_SECS: i64 = 60;
        let skew = Duration::seconds(ALLOWED_SKEW_SECS);

        // Check Date header (request or response)
        if let Some(hv) = tx.request.headers.get_all("date").iter().next() {
            if let Ok(s) = hv.to_str() {
                // This is a *recipient* parse: `parse_http_date_to_datetime` owns the
                // §5.6.7 HTTP-date grammar and the accept-all-three-formats obligation
                // (so those quotes live there, not duplicated here). The failure below
                // therefore fires only on an unparseable value — hence "HTTP-date",
                // not "IMF-fixdate"; the sender's IMF-fixdate obligation is a separate
                // rule's concern. This rule's own claim is only what Date *is*:
                // cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated"
                if crate::http_date::parse_http_date_to_datetime(s).is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Date header is not a valid HTTP-date (RFC 9110 §5.6.7)".into(),
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
            // Response Date check — same recipient parse as the request Date above.
            // cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated"
            if let Some(hv) = resp.headers.get_all("date").iter().next() {
                if let Ok(s) = hv.to_str() {
                    if crate::http_date::parse_http_date_to_datetime(s).is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Date header is not a valid HTTP-date (RFC 9110 §5.6.7)"
                                .into(),
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
                                        // cite(RFC 9110 § 8.8.2.1): "An origin server with a clock (as defined in Section 5.6.7) MUST NOT generate a Last-Modified date that is later than the server's time of message origination (Date, Section 6.6.1)."
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

                    // Sunset header: a valid HTTP-date that SHOULD be in the future.
                    // One §3 sentence licenses both halves — the HTTP-date format and
                    // the future check below (the skew makes the past-check lenient).
                    // cite(RFC 8594 § 3): "The Sunset value is an HTTP-date timestamp, as defined in Section 7.1.1.1 of [RFC7231], and SHOULD be a timestamp in the future."
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
                                        message: "Sunset header is not a valid HTTP-date (RFC 8594 §3)".into(),
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

        // Request-level If-Modified-Since: if a Date header is present, flag an
        // If-Modified-Since later than it. No spec sentence mandates this ordering
        // (a conditional date after the request's own Date is merely nonsensical),
        // so it is a reasonableness heuristic — uncited, recorded in the ledger. The
        // format of If-Modified-Since is owned by its dedicated rule (parse errors
        // are skipped here to avoid duplicate reports).
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

    fn title(&self) -> Option<&'static str> {
        Some("Message Date and Time Headers Consistency")
    }

    fn description(&self) -> &'static str {
        "Validate that date/time related headers are well-formed and mutually consistent. Each header is parsed as an HTTP-date (a recipient accepts all three formats; the sender-only IMF-fixdate obligation is checked by the per-header format rules), then compared: `Last-Modified` MUST NOT be later than `Date` (RFC 9110 §8.8.2.1), `Sunset` SHOULD indicate a future time relative to `Date` (RFC 8594 §3), and — as a reasonableness check with no direct spec basis — a conditional-request `If-Modified-Since` should not be later than the request's own `Date`. A small clock-skew tolerance is allowed. Values that are not a parseable HTTP-date, or that contain non-UTF8 bytes, are flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1",
                note: "`Date` header (parsed as HTTP-date for comparison)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.8.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
                note: "`Last-Modified` header",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("13.1.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
                note: "`If-Modified-Since` (conditional requests)",
            },
            crate::rules::SpecRef {
                spec: "RFC 8594",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc8594.html#section-3",
                note: "`Sunset` header semantics",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nLast-Modified: Wed, 21 Oct 2015 07:20:00 GMT\nSunset: Tue, 01 Jan 2030 00:00:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nLast-Modified: Wed, 21 Oct 2015 07:30:00 GMT  # Last-Modified after Date\nSunset: Wed, 21 Oct 2015 07:27:00 GMT        # Sunset is in the past relative to Date",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageDateAndTimeHeadersConsistency;

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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Date header is not a valid HTTP-date") || m.contains("non-UTF8"));
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset header is not a valid HTTP-date"));
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Date header is not a valid HTTP-date"));
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
