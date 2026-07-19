// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCrossOriginResourcePolicyValid;

impl Rule for MessageCrossOriginResourcePolicyValid {
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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

        // Acceptable values: same-site, same-origin, cross-origin — and the ABNF says
        // case-sensitive, so this comparison is too. It used to be case-insensitive, which
        // called `SAME-ORIGIN` valid; a user agent does not. It sets an unrecognized policy
        // to null and fetches the resource as if the header were never sent, so accepting
        // the miscased form told the operator a protection was on while it was off.
        // cite(Fetch): "Cross-Origin-Resource-Policy = %s"same-origin" / %s"same-site" / %s"cross-origin" ; case-sensitive"
        // cite(Fetch): "If policy is neither `same-origin`, `same-site`, nor `cross-origin`, then set policy to null."
        if val == "same-site" || val == "same-origin" || val == "cross-origin" {
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

    fn title(&self) -> Option<&'static str> {
        Some("Cross-Origin Resource Policy Value")
    }

    fn description(&self) -> &'static str {
        "This rule checks the `Cross-Origin-Resource-Policy` response header value and ensures it is one of the allowed tokens: **`same-site`**, **`same-origin`**, or **`cross-origin`**. The comparison is **case-sensitive**, as the Fetch Standard's ABNF requires: a user agent that does not recognize the value sets the policy to null and serves the resource as though the header were never sent, so a miscased `SAME-ORIGIN` is not a weaker protection but no protection at all. Surrounding whitespace is still tolerated. The header must be a single value and must not contain comma-separated lists or multiple header fields. This header is response-only; the rule applies to server responses (RuleScope::Server)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "Fetch",
                section: None,
                url: "https://fetch.spec.whatwg.org/",
                note: "W3C: Cross-Origin Resource Policy",
            },
            crate::rules::SpecRef {
                spec: "MDN Cross-Origin-Resource-Policy",
                section: None,
                url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy",
                note: "Cross-Origin-Resource-Policy",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Resource-Policy: same-site",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(case-insensitive, trailing whitespace allowed)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Resource-Policy: SAME-ORIGIN ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unsupported value)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Resource-Policy: private",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(comma-separated list)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Resource-Policy: same-origin, cross-origin",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageCrossOriginResourcePolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("same-site"), false)]
    #[case(Some("same-origin"), false)]
    #[case(Some("cross-origin"), false)]
    // Surrounding whitespace is still stripped, but the token itself is case-sensitive:
    // a user agent sets `SAME-ORIGIN` to null and serves the resource unprotected, so
    // calling it valid would report a protection that is not there.
    #[case(Some(" same-origin "), false)]
    // invalid
    #[case(Some(" SAME-ORIGIN "), true)]
    #[case(Some("Same-Origin"), true)]
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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

        rule.validate(&cfg)?;
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .unwrap();
        assert!(v.message.contains("single value"));
    }
}
