// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `immutable` is only meaningful while a response is fresh, so pairing it with a
/// directive that guarantees the response is never fresh — `no-store`, `no-cache`,
/// `max-age=0`, `s-maxage=0` — is a contradiction: the promise has no window in
/// which to apply.
///
/// This replaces `server_must_revalidate_and_immutable_mismatch`, which flagged
/// `immutable` alongside `must-revalidate`. That pairing is *correct*, not a mistake:
/// the two govern disjoint windows — `immutable` while fresh, `must-revalidate` once
/// stale — and RFC 8246 Section 2 says stale responses are revalidated as they
/// normally would be. The old rule reported coherent configurations as errors, and
/// no sentence in RFC 9111 or RFC 8246 could be found to justify it.
pub struct ServerImmutableRequiresFreshness;

/// Directives that leave a response with no freshness lifetime at all. Each is a
/// reason `immutable` standing next to it is dead text.
const NEVER_FRESH: &[&str] = &["no-store", "no-cache", "max-age=0", "s-maxage=0"];

impl Rule for ServerImmutableRequiresFreshness {
    fn id(&self) -> &'static str {
        "server_immutable_requires_freshness"
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

        let mut found_immutable = false;
        let mut conflicting: Option<String> = None;

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
                let (name, value) = match member.split_once('=') {
                    Some((n, v)) => (n.trim(), Some(v.trim())),
                    None => (member, None),
                };
                let lname = name.to_ascii_lowercase();

                if lname == "immutable" {
                    found_immutable = true;
                    continue;
                }

                let normalized = match (lname.as_str(), value) {
                    // A zero lifetime is a zero lifetime however it is spelled.
                    ("max-age" | "s-maxage", Some(v)) if v.parse::<u64>() == Ok(0) => {
                        format!("{}=0", lname)
                    }
                    ("no-store" | "no-cache", None) => lname.clone(),
                    // A qualified `no-cache="field"` restricts reuse of the listed fields
                    // only; the response still has a freshness lifetime, so `immutable`
                    // still has a window to apply to.
                    _ => continue,
                };

                if NEVER_FRESH.contains(&normalized.as_str()) && conflicting.is_none() {
                    conflicting = Some(normalized);
                }
            }
        }

        // `immutable` promises the representation will not change *while the response is
        // fresh*, and asks clients not to revalidate during that window. A directive that
        // leaves no such window makes the promise unsatisfiable: one of the two is dead
        // text, and the server does not know which of them it meant.
        // cite(RFC 8246 § 2): "The immutable extension only applies during the freshness lifetime of the stored response."
        // cite(RFC 8246 § 2): "Clients SHOULD NOT issue a conditional request during the response's freshness lifetime (e.g., upon a reload) unless explicitly overridden by the user (e.g., a force reload)."
        if let (true, Some(conflict)) = (found_immutable, conflicting) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Cache-Control pairs 'immutable' with '{}', which leaves the response no freshness lifetime; 'immutable' only applies during one, so it has no effect here",
                    conflict
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Immutable Requires Freshness")
    }

    fn description(&self) -> &'static str {
        "This rule flags responses whose `Cache-Control` header pairs `immutable` with a directive that leaves the response no freshness lifetime — `no-store`, `no-cache`, `max-age=0`, or `s-maxage=0`. Per RFC 8246, `immutable` only applies during a stored response's freshness lifetime: it tells clients the representation will not change while the response is fresh, and asks them not to revalidate during that window. A response that can never be fresh has no such window, so `immutable` has nothing to act on, and one of the two directives is a mistake.\n\nNote: `immutable` together with `must-revalidate` is **not** flagged. Those directives govern disjoint windows — `immutable` applies while the response is fresh, `must-revalidate` binds once it has gone stale — and RFC 8246 says stale responses \"SHOULD be revalidated as they normally would be in the absence of the immutable extension\". `Cache-Control: max-age=3600, immutable, must-revalidate` is coherent. An earlier version of this rule (`server_must_revalidate_and_immutable_mismatch`) reported that pairing as an error. It was wrong: no sentence in RFC 9111 or RFC 8246 supported it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 8246",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc8246.html#section-2",
                note: "The `immutable` Cache-Control extension — applies only during the freshness lifetime",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2",
                note: "Response directives: `no-store`, `no-cache`, `max-age`, `s-maxage`",
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
                compliance: Compliance::Compliant,
                label: Some("Response (immutable while fresh, revalidated once stale)"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: max-age=3600, immutable, must-revalidate",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: no-cache, immutable",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: max-age=0, immutable",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerImmutableRequiresFreshness;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // No freshness lifetime for `immutable` to apply to.
    #[case(Some("no-cache, immutable"), true)]
    #[case(Some("no-store, immutable"), true)]
    #[case(Some("max-age=0, immutable"), true)]
    #[case(Some("s-maxage=0, immutable, max-age=600"), true)]
    #[case(Some("IMMUTABLE, NO-CACHE"), true)]
    #[case(Some("immutable, max-age = 0"), true)]
    // Coherent: `immutable` governs the fresh window, `must-revalidate` the stale one.
    // The rule this one replaces reported the first of these as an error.
    #[case(Some("max-age=3600, immutable, must-revalidate"), false)]
    #[case(Some("immutable, max-age=3600"), false)]
    #[case(Some("must-revalidate, max-age=0"), false)]
    #[case(Some("no-cache, max-age=0"), false)]
    // Qualified `no-cache` restricts named fields only; the response still has a
    // freshness lifetime, so `immutable` still has a window to apply to.
    #[case(Some("no-cache=\"Set-Cookie\", immutable, max-age=600"), false)]
    #[case(None, false)]
    fn cache_control_cases(#[case] cc: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerImmutableRequiresFreshness;

        let tx = match cc {
            Some(v) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cache-control", v)],
            ),
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let cfg = crate::test_helpers::make_test_config_with_severity(
            "server_immutable_requires_freshness",
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
            .append("cache-control", HeaderValue::from_static("no-store"));

        let rule = ServerImmutableRequiresFreshness;
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "server_immutable_requires_freshness",
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

        let rule = ServerImmutableRequiresFreshness;
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
        let rule = ServerImmutableRequiresFreshness;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ServerImmutableRequiresFreshness;
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
