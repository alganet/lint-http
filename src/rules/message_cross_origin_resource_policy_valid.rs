// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCrossOriginResourcePolicyValid;

impl Rule for MessageCrossOriginResourcePolicyValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cross_origin_resource_policy_valid"
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
        // CORP is a response-only header per spec; ignore requests
        let resp = if let Some(resp) = &tx.response {
            resp
        } else {
            return None;
        };
        let headers = &resp.headers;

        let count = headers
            .get_all("cross-origin-resource-policy")
            .iter()
            .count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Cross-Origin-Resource-Policy header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(
            headers,
            "cross-origin-resource-policy",
        ) {
            Some(v) => v.trim(),
            None => return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Cross-Origin-Resource-Policy header contains non-ASCII or control characters"
                        .into(),
            }),
        };

        // Must not be a comma-separated list
        if crate::helpers::headers::parse_list_header(val).count() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Cross-Origin-Resource-Policy must be a single value".into(),
            });
        }

        // Acceptable values: same-site, same-origin, cross-origin (case-insensitive)
        if val.eq_ignore_ascii_case("same-site")
            || val.eq_ignore_ascii_case("same-origin")
            || val.eq_ignore_ascii_case("cross-origin")
        {
            return None;
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Cross-Origin-Resource-Policy contains unsupported value: '{}'",
                val
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{make_test_rule_config, make_test_transaction};

    #[rstest]
    #[case(Some("same-site"), false)]
    #[case(Some("same-origin"), false)]
    #[case(Some("cross-origin"), false)]
    #[case(Some(" SAME-ORIGIN "), false)]
    // invalid
    #[case(Some(""), true)]
    #[case(Some("other"), true)]
    #[case(Some("same-origin, cross-origin"), true)]
    fn check_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageCrossOriginResourcePolicyValid;
        let mut tx = make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cross-origin-resource-policy", v)],
            );
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}', got none", val);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{:?}': got {:?}",
                val,
                v
            );
        }
    }

    #[test]
    fn no_response_no_violation() {
        let rule = MessageCrossOriginResourcePolicyValid;
        let tx = make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_headers_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageCrossOriginResourcePolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-resource-policy", "same-site")]);
        hdrs.append(
            "cross-origin-resource-policy",
            HeaderValue::from_static("cross-origin"),
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
        assert!(v
            .unwrap()
            .message
            .contains("Multiple Cross-Origin-Resource-Policy"));
    }

    #[test]
    fn non_utf8_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageCrossOriginResourcePolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-resource-policy", "same-site")]);
        hdrs.insert(
            "cross-origin-resource-policy",
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
    fn scope_is_server() {
        let rule = MessageCrossOriginResourcePolicyValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageCrossOriginResourcePolicyValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_cross_origin_resource_policy_valid".into(),
            toml::Value::Table(table),
        );

        let _ = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn trailing_whitespace_is_accepted() {
        let rule = MessageCrossOriginResourcePolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-resource-policy", "same-origin ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_value_reports_value() {
        let rule = MessageCrossOriginResourcePolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-resource-policy", "other")],
        );
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_test_rule_config(),
            )
            .unwrap();
        assert!(v.message.contains("unsupported value"));
        assert!(v.message.contains("other"));
    }

    #[test]
    fn comma_list_reports_single_value_message() {
        let rule = MessageCrossOriginResourcePolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-resource-policy", "same-origin, cross-origin")],
        );
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_test_rule_config(),
            )
            .unwrap();
        assert!(v.message.contains("single value"));
    }
}
