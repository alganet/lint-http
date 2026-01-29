// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageOriginIsolatedHeaderValidity;

impl Rule for MessageOriginIsolatedHeaderValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_origin_isolated_header_validity"
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
        let resp = if let Some(r) = &tx.response {
            r
        } else {
            return None;
        };

        let count = resp.headers.get_all("origin-isolation").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Origin-Isolation header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(&resp.headers, "origin-isolation") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Origin-Isolation header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // Must not be a comma-separated list
        if crate::helpers::headers::parse_list_header(val).count() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Origin-Isolation must be a single value".into(),
            });
        }

        // Accept only structured-headers boolean true value '?1' to signal origin isolation
        if val.eq("?1") {
            return None;
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("Origin-Isolation header value '{}' is invalid: expected '?1' to enable origin isolation", val),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("?1"), false)]
    #[case(Some(" ?1 "), false)]
    #[case(Some("?0"), true)]
    #[case(Some("1"), true)]
    #[case(Some("?1, ?1"), true)]
    #[case(Some(""), true)]
    fn check_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageOriginIsolatedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("origin-isolation", v)],
            );
        }

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
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
    fn multiple_headers_violation() {
        use hyper::header::HeaderValue;
        let rule = MessageOriginIsolatedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs = crate::test_helpers::make_headers_from_pairs(&[("origin-isolation", "?1")]);
        hdrs.append("origin-isolation", HeaderValue::from_static("?1"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Origin-Isolation"));
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageOriginIsolatedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs = crate::test_helpers::make_headers_from_pairs(&[("origin-isolation", "?1")]);
        hdrs.insert("origin-isolation", HeaderValue::from_bytes(&[0xff])?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_is_violation_message_contains_hint() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageOriginIsolatedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs = crate::test_helpers::make_headers_from_pairs(&[("origin-isolation", "?1")]);
        hdrs.insert("origin-isolation", HeaderValue::from_bytes(&[0xff])?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-ASCII") || msg.contains("control"));
        Ok(())
    }

    #[test]
    fn invalid_value_includes_value_in_message() {
        let rule = MessageOriginIsolatedHeaderValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("origin-isolation", "?0")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("?0"));
    }

    #[test]
    fn comma_list_reports_single_value_message() {
        let rule = MessageOriginIsolatedHeaderValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("origin-isolation", "?1, ?1")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("single value"));
    }

    #[test]
    fn no_response_returns_none() {
        let rule = MessageOriginIsolatedHeaderValidity;
        let tx = crate::test_helpers::make_test_transaction(); // no response set
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_server() {
        let r = MessageOriginIsolatedHeaderValidity;
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageOriginIsolatedHeaderValidity;
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_origin_isolated_header_validity");
        let _engine = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
