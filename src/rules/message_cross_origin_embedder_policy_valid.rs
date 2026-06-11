// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCrossOriginEmbedderPolicyValid;

impl Rule for MessageCrossOriginEmbedderPolicyValid {
    fn id(&self) -> &'static str {
        "message_cross_origin_embedder_policy_valid"
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
        // COEP is a response-only header per spec; ignore requests
        let resp = if let Some(resp) = &tx.response {
            resp
        } else {
            return None;
        };
        let headers = &resp.headers;

        let count = headers
            .get_all("cross-origin-embedder-policy")
            .iter()
            .count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Cross-Origin-Embedder-Policy header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(
            headers,
            "cross-origin-embedder-policy",
        ) {
            Some(v) => v.trim(),
            None => return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Cross-Origin-Embedder-Policy header contains non-ASCII or control characters"
                        .into(),
            }),
        };

        // Must not be a comma-separated list
        if crate::helpers::headers::parse_list_header(val).count() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Cross-Origin-Embedder-Policy must be a single value".into(),
            });
        }

        // Acceptable values for our correctness check: require-corp or credentialless (case-insensitive)
        if val.eq_ignore_ascii_case("require-corp") || val.eq_ignore_ascii_case("credentialless") {
            return None;
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Cross-Origin-Embedder-Policy value '{}' does not enable cross-origin isolation (use 'require-corp' or 'credentialless')",
                val
            ),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("Cross-Origin-Embedder-Policy Value")
    }

    fn description(&self) -> &'static str {
        "This rule checks the `Cross-Origin-Embedder-Policy` response header value and ensures it uses one of the secure tokens that enable cross-origin isolation: **`require-corp`** or **`credentialless`**. The header must be a single value and must not contain comma-separated lists or multiple header fields. Note: `unsafe-none` is a valid COEP token per the specification, but it does not enable cross-origin isolation; this rule rejects it intentionally to encourage more secure configurations. The rule applies to server responses (RuleScope::Server)."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "MDN: Cross-Origin-Embedder-Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
            "Cross-Origin Embedder Policy (W3C): The Cross-Origin-Embedder-Policy header — https://w3c.github.io/webappsec-coep/",
            "HTML Standard / Fetch (describes behavior and interaction with other cross-origin policies) — https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(response)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Embedder-Policy: require-corp",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(case-insensitive, whitespace tolerated)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Embedder-Policy:  CREDENTIALLESS  ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(valid but insecure value)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Embedder-Policy: unsafe-none",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(comma-separated list)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Embedder-Policy: require-corp, credentialless",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Embedder-Policy: require-corp\nCross-Origin-Embedder-Policy: unsafe-none",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageCrossOriginEmbedderPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("require-corp"), false)]
    #[case(Some("credentialless"), false)]
    #[case(Some(" REQUIRE-CORP "), false)]
    // invalid
    #[case(Some(""), true)]
    #[case(Some("unsafe-none"), true)]
    #[case(Some("other"), true)]
    #[case(Some("require-corp, credentialless"), true)]
    fn check_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let mut tx = make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cross-origin-embedder-policy", v)],
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
        let rule = MessageCrossOriginEmbedderPolicyValid;
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

        let rule = MessageCrossOriginEmbedderPolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-embedder-policy", "require-corp")]);
        hdrs.append(
            "cross-origin-embedder-policy",
            HeaderValue::from_static("credentialless"),
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
            .contains("Multiple Cross-Origin-Embedder-Policy"));
    }

    #[test]
    fn non_utf8_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageCrossOriginEmbedderPolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-embedder-policy", "require-corp")]);
        hdrs.insert(
            "cross-origin-embedder-policy",
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
        let rule = MessageCrossOriginEmbedderPolicyValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_cross_origin_embedder_policy_valid".into(),
            toml::Value::Table(table),
        );

        rule.validate(&cfg)?;
        Ok(())
    }

    #[test]
    fn trailing_whitespace_is_accepted() {
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-embedder-policy", "require-corp ")],
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
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-embedder-policy", "unsafe-none")],
        );
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .unwrap();
        assert!(v.message.contains("does not enable cross-origin isolation"));
        assert!(v.message.contains("unsafe-none"));
    }

    #[test]
    fn comma_list_reports_single_value_message() {
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "cross-origin-embedder-policy",
                "require-corp, credentialless",
            )],
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

    #[test]
    fn validate_rules_with_valid_config_case_insensitive() -> anyhow::Result<()> {
        // Ensure rule validates configuration and accepts case-insensitive header values
        let rule = MessageCrossOriginEmbedderPolicyValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_cross_origin_embedder_policy_valid".into(),
            toml::Value::Table(table),
        );

        // validate configuration parsing still succeeds
        rule.validate(&cfg)?;

        // Mixed-case header value must be accepted (case-insensitive)
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-embedder-policy", "CrEdEntIalLess")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "expected no violation for mixed-case value");

        Ok(())
    }
}
