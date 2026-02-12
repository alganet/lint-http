// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use chrono::TimeZone;

pub struct MessageSunsetAndDeprecationConsistency;

impl Rule for MessageSunsetAndDeprecationConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_sunset_and_deprecation_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // This rule inspects response headers only
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // only applies to responses
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Get Sunset header (HTTP-date) if present and parseable
        let sunset_opt = match crate::helpers::headers::get_header_str(&resp.headers, "sunset") {
            Some(s) => match crate::http_date::parse_http_date_to_datetime(s) {
                Ok(dt) => Some((s.to_string(), dt)),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Sunset header is not a valid IMF-fixdate (RFC 8594)".into(),
                    });
                }
            },
            None => None,
        };

        // Get Deprecation header (structured '@<seconds>' form) if present and parseable
        // We intentionally only consider the structured '@' form here; legacy forms are
        // validated by `server_deprecation_header_syntax` and we avoid duplicate errors.
        let deprecation_opt = match resp.headers.get_all("deprecation").iter().next() {
            Some(hv) => match hv.to_str() {
                Ok(s_raw) => {
                    let s = s_raw.trim();
                    if s.starts_with('@')
                        && s.len() > 1
                        && s[1..].chars().all(|c| c.is_ascii_digit())
                    {
                        // parse seconds since epoch
                        match s[1..].parse::<i64>() {
                            Ok(secs) => {
                                // Build a UTC DateTime safely from epoch seconds.
                                chrono::Utc
                                    .timestamp_opt(secs, 0)
                                    .single()
                                    .map(|dt| (s.to_string(), dt)) // treat out-of-range as non-parseable
                            }
                            Err(_) => None,
                        }
                    } else {
                        // Not structured '@' form -> ignore here (other rule flags legacy forms)
                        None
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Deprecation header contains non-UTF8 value".into(),
                    })
                }
            },
            None => None,
        };

        // If both parseable values present, ensure logical ordering:
        // Deprecation timestamp SHOULD be <= Sunset datetime (deprecation happens before removal)
        if let (Some((dep_raw, dep_dt)), Some((sun_raw, sun_dt))) = (deprecation_opt, sunset_opt) {
            // allow small skew (60s) for clock/time-format differences
            let allowed_skew = chrono::Duration::seconds(60);
            if dep_dt > sun_dt + allowed_skew {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Deprecation '{}' indicates a time after Sunset '{}'; Deprecation should be earlier than or equal to Sunset",
                        dep_raw, sun_raw
                    ),
                });
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
    fn consistent_deprecation_and_sunset_ok() {
        // Deprecation @0 (1970) obviously <= far-future Sunset
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@0"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if let Some(v) = &v {
            eprintln!(
                "unexpected violation: rule={} message={}",
                v.rule, v.message
            );
        }
        assert!(v.is_none());
    }

    #[rstest]
    fn deprecation_after_sunset_reports_violation() {
        // Deprecation @4102444800 (2100-01-01) is after Sunset 2030 -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@4102444800"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Deprecation") && msg.contains("Sunset"));
    }

    #[rstest]
    fn legacy_deprecation_ignored_by_this_rule() {
        // Deprecation legacy 'true' is handled by server_deprecation_header_syntax; this rule should not duplicate it
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "true"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn missing_sunset_or_deprecation_no_violation() {
        let tx1 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("sunset", "Tue, 01 Jan 2030 00:00:00 GMT")],
        );
        let tx2 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("deprecation", "@0")]);
        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx1, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
        assert!(rule
            .check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }

    #[rstest]
    fn non_utf8_deprecation_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.insert(
            "sunset",
            HeaderValue::from_static("Tue, 01 Jan 2030 00:00:00 GMT"),
        );
        hm.insert("deprecation", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
    }

    #[test]
    fn parseable_but_non_structured_deprecation_ignored() {
        // Deprecation as HTTP-date is parsed as legacy by server_deprecation_header_syntax;
        // this rule only checks structured '@' values, so it should not error here.
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "Tue, 01 Jan 2025 00:00:00 GMT"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn sunset_invalid_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("sunset", "not-a-date"), ("deprecation", "@0")],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Sunset header is not a valid IMF-fixdate"));
    }

    #[test]
    fn deprecation_equal_to_sunset_ok() {
        // Sunset: Tue, 01 Jan 2030 00:00:00 GMT -> epoch 1893456000
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456000"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }

    #[test]
    fn deprecation_within_allowed_skew_ok() {
        // Sunset epoch 1893456000; dep = sunset + 30s -> allowed
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456030"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }

    #[test]
    fn deprecation_just_over_allowed_skew_reports_violation() {
        // dep = sunset + 61s -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456061"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn structured_deprecation_nondigits_ignored_here() {
        // server_deprecation_header_syntax flags '@abc' as invalid; this rule ignores non-structured forms
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@abc"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }

    #[test]
    fn structured_deprecation_overflow_ignored_here() {
        // extremely large numeric value that doesn't parse into i64 should be ignored by this rule
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@999999999999999999999999"),
            ],
        );
        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }

    #[test]
    fn non_utf8_sunset_ignored_and_no_panic() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.insert("sunset", HeaderValue::from_bytes(&[0xff]).unwrap());
        hm.insert("deprecation", HeaderValue::from_static("@0"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let rule = MessageSunsetAndDeprecationConsistency;
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_none());
    }
    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_sunset_and_deprecation_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageSunsetAndDeprecationConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
