// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAccessControlAllowOriginValid;

impl Rule for MessageAccessControlAllowOriginValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_access_control_allow_origin_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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

        let headers = &resp.headers;

        let acao_count = headers
            .get_all("access-control-allow-origin")
            .iter()
            .count();
        if acao_count == 0 {
            return None;
        }

        // Multiple header fields are not allowed for Access-Control-Allow-Origin.
        if acao_count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Access-Control-Allow-Origin header fields present; only a single value ('*' or a single origin) is allowed".into(),
            });
        }

        // There is a single header field; validate its single value semantics and origin syntax.
        let hv = headers
            .get_all("access-control-allow-origin")
            .iter()
            .next()
            .unwrap();
        let s = match hv.to_str() {
            Ok(v) => v.trim(),
            Err(_) => return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Access-Control-Allow-Origin header contains non-ASCII or control characters"
                        .into(),
            }),
        };

        // Must be a single value (not a comma-separated list)
        let members: Vec<String> = crate::helpers::headers::parse_list_header(s)
            .map(|m| m.to_string())
            .collect();
        if members.len() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Access-Control-Allow-Origin must be a single value ('*', 'null', or a serialized origin)".into(),
            });
        }

        let member = members.into_iter().next().unwrap();
        if member == "*" || member.eq_ignore_ascii_case("null") {
            return None;
        }

        if !crate::helpers::headers::is_valid_serialized_origin(&member) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Access-Control-Allow-Origin contains invalid origin: '{}'",
                    member
                ),
            });
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
        let rule = MessageAccessControlAllowOriginValid;
        let tx = make_test_transaction();
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn response_without_acao_header_returns_none() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    #[case("*")]
    #[case("null")]
    #[case("https://example.com")]
    #[case("  https://example.com  ")]
    fn valid_single_values(#[case] val: &str) {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", val)],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(
            v.is_none(),
            "expected no violation for '{}': got {:?}",
            val,
            v
        );
    }

    #[test]
    fn comma_separated_values_are_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://a, https://b")],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("single value"));
    }

    #[test]
    fn multiple_header_fields_are_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.append(
            "access-control-allow-origin",
            HeaderValue::from_static("https://b"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple"));
    }

    #[test]
    fn invalid_origin_is_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "example.com")],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageAccessControlAllowOriginValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageAccessControlAllowOriginValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_access_control_allow_origin_valid".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
