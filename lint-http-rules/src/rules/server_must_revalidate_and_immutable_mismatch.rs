// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Cache-Control` response must not contain both `must-revalidate` and `immutable`.
/// `must-revalidate` requires caches to revalidate when stale, while `immutable`
/// indicates the response is intended to be long-lived (RFC 8246) and is not
/// appropriate to pair with `must-revalidate` in the same response.
pub struct ServerMustRevalidateAndImmutableMismatch;

impl Rule for ServerMustRevalidateAndImmutableMismatch {
    fn id(&self) -> &'static str {
        "server_must_revalidate_and_immutable_mismatch"
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
        let resp = tx.response.as_ref()?;

        // Collect all cache-control directive tokens across header fields
        let mut found_must_revalidate = false;
        let mut found_immutable = false;

        for hv in resp.headers.get_all("cache-control").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Cache-Control header contains non-UTF8 value".into(),
                    })
                }
            };

            for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
                let member = member.trim();
                if member.is_empty() {
                    continue;
                }
                // directive may be token or token=...; take token name
                let name = member
                    .split('=')
                    .next()
                    .expect("split always yields at least one item")
                    .trim();
                let lname = name.to_ascii_lowercase();
                if lname == "must-revalidate" {
                    found_must_revalidate = true;
                }
                if lname == "immutable" {
                    found_immutable = true;
                }
            }
        }

        if found_must_revalidate && found_immutable {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Cache-Control contains both 'must-revalidate' and 'immutable' which is contradictory".into(),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Must-Revalidate and Immutable Mismatch")
    }

    fn description(&self) -> &'static str {
        "This rule flags responses whose `Cache-Control` header contains both `must-revalidate` and `immutable`. These directives have conflicting operational implications: `must-revalidate` requires caches to revalidate once a response becomes stale, while `immutable` signals that a response is intended to remain unchanged and avoid revalidation during its freshness lifetime (RFC 8246). Having both in the same response is likely a configuration mistake."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.2.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2",
                note: "`must-revalidate`",
            },
            crate::rules::SpecRef {
                spec: "RFC 8246",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc8246.html",
                note: "HTTP Immutable Responses (`immutable` directive)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: max-age=604800, immutable",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: max-age=3600, immutable, must-revalidate",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerMustRevalidateAndImmutableMismatch;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("max-age=3600, immutable, must-revalidate"), true)]
    #[case(Some("IMMUTABLE, MUST-REVALIDATE"), true)]
    #[case(Some("immutable, must-revalidate=1"), true)]
    #[case(Some("immutable, max-age=3600"), false)]
    #[case(Some("must-revalidate, max-age=0"), false)]
    #[case(Some("public, immutable, must-revalidate"), true)]
    #[case(None, false)]
    fn cache_control_cases(#[case] cc: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerMustRevalidateAndImmutableMismatch;

        let tx = match cc {
            Some(v) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cache-control", v)],
            ),
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let cfg = crate::test_helpers::make_test_config_with_severity(
            "server_must_revalidate_and_immutable_mismatch",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for cc={:?}", cc);
        } else {
            assert!(v.is_none(), "unexpected violation for cc={:?}: {:?}", cc, v);
        }
    }

    #[test]
    fn multiple_header_fields_combined() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("cache-control", HeaderValue::from_static("immutable"));
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("cache-control", HeaderValue::from_static("must-revalidate"));

        let rule = ServerMustRevalidateAndImmutableMismatch;
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "server_must_revalidate_and_immutable_mismatch",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("cache-control", bad);

        let rule = ServerMustRevalidateAndImmutableMismatch;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerMustRevalidateAndImmutableMismatch;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ServerMustRevalidateAndImmutableMismatch;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert(rule.id().to_string(), toml::Value::Table(table));
        rule.validate(&cfg)?;
        Ok(())
    }
}
