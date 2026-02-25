// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageTimingAllowOriginValidity;

impl Rule for MessageTimingAllowOriginValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_timing_allow_origin_validity"
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

        let headers = &resp.headers;

        let tao_count = headers.get_all("timing-allow-origin").iter().count();
        if tao_count == 0 {
            return None;
        }

        // Combine members across multiple header fields; parse_list_header handles commas & whitespace
        for hv in headers.get_all("timing-allow-origin").iter() {
            let s =
                match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Timing-Allow-Origin header contains non-ASCII or control characters"
                                .into(),
                    }),
                };

            // Empty header value (only whitespace) is invalid
            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Timing-Allow-Origin header value is empty".into(),
                });
            }

            // Detect empty list members caused by consecutive commas or leading empty members.
            // Trailing empty members (e.g., "https://a, ") are tolerated.
            let parts: Vec<&str> = s.split(',').collect();
            for (i, raw_member) in parts.iter().enumerate() {
                if raw_member.trim().is_empty() {
                    // If any non-empty member appears after this empty one, it's an internal/leading empty member -> violation.
                    if parts.iter().skip(i + 1).any(|p| !p.trim().is_empty()) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Timing-Allow-Origin header contains empty member".into(),
                        });
                    }
                    // Otherwise it's trailing empty member(s); tolerated.
                }
            }
            for member in crate::helpers::headers::parse_list_header(s) {
                let m = member.trim();

                if m == "*" || m.eq_ignore_ascii_case("null") {
                    continue;
                }

                if !crate::helpers::headers::is_valid_serialized_origin(m) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Timing-Allow-Origin contains invalid origin: '{}'", m),
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

    use crate::test_helpers::{make_test_rule_config, make_test_transaction};

    #[test]
    fn no_response_no_violation() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_without_header_returns_none() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    #[case("*")]
    #[case("null")]
    #[case("https://example.com")]
    #[case("  https://example.com  ")]
    #[case("https://a, https://b")]
    fn valid_values(#[case] val: &str) {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(
            v.is_none(),
            "expected no violation for '{}': got {:?}",
            val,
            v
        );
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageTimingAllowOriginValidity;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.insert(
            "timing-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn trailing_comma_is_allowed() {
        // Helper parsing ignores empty members (trailing commas are tolerated); no violation expected
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https://a,  ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(
            v.is_none(),
            "expected no violation for trailing comma: got {:?}",
            v
        );
    }

    #[test]
    fn empty_value_is_violation() {
        let rule = MessageTimingAllowOriginValidity;
        // header present but empty value -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", " ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty"));
    }

    #[test]
    fn ipv6_origin_is_valid() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https://[::1]:8080")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn wildcard_and_origin_mix_is_accepted() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "*, https://example.com")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn null_case_insensitive_is_accepted() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "NULL")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn invalid_origin_is_violation() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https:///foo")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn multiple_header_fields_are_combined() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageTimingAllowOriginValidity;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.append("timing-allow-origin", HeaderValue::from_static("https://b"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(
            v.is_none(),
            "expected no violation for combined fields: got {:?}",
            v
        );
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageTimingAllowOriginValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageTimingAllowOriginValidity;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_timing_allow_origin_validity".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
