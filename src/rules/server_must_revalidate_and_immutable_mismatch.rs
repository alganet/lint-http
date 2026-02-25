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
    type Config = crate::rules::RuleConfig;

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
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

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
}

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

        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

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
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

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
            &crate::test_helpers::make_test_rule_config(),
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
        let _ = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
