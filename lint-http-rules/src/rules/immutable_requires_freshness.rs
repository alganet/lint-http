// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `immutable` only acts while a response is fresh, so pairing it with a directive that
/// leaves the promise nothing to act on is a contradiction. Each flagged directive nullifies
/// the window a different way: `no-store` prevents storing at all, `no-cache` mandates
/// revalidation before reuse, `max-age=0` zeroes the freshness lifetime, and `s-maxage=0`
/// does the same for shared caches.
///
/// This replaces `server_must_revalidate_and_immutable_mismatch`, which flagged
/// `immutable` alongside `must-revalidate`. That pairing is *correct*, not a mistake:
/// the two govern disjoint windows — `immutable` while fresh, `must-revalidate` once
/// stale — and RFC 8246 Section 2 says stale responses are revalidated as they
/// normally would be. The old rule reported coherent configurations as errors, and
/// no sentence in RFC 9111 or RFC 8246 could be found to justify it.
pub struct ImmutableRequiresFreshness;

/// Directives that nullify `immutable`'s fresh-window promise — each either prevents storing
/// the response (`no-store`), mandates revalidation before reuse (`no-cache`), or zeroes the
/// freshness lifetime (`max-age=0`; `s-maxage=0` for shared caches). Any of them makes
/// `immutable` standing next to it dead text. (Not "no freshness lifetime at all": `no-cache`
/// with a positive `max-age` is still *fresh*, it just cannot be reused without revalidation.)
const NEVER_FRESH: &[&str] = &["no-store", "no-cache", "max-age=0", "s-maxage=0"];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_8246_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8246",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc8246.html#section-2",
    note: "The `immutable` Cache-Control extension — applies only during the freshness lifetime",
};
const RFC_9111_5_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2",
    note: "Response directives: `no-store`, `no-cache`, `max-age`, `s-maxage`",
};

impl Rule for ImmutableRequiresFreshness {
    fn id(&self) -> &'static str {
        "immutable_requires_freshness"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;

            let mut found_immutable = false;
            let mut conflicting: Option<String> = None;

            for hv in resp.headers.get_all("cache-control").iter() {
                let s = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => {
                        return Some(self.violation(
                            ctx.severity,
                            "Cache-Control header contains non-UTF8 value".into(),
                        ))
                    }
                };

                for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
                    if member.is_empty() {
                        continue;
                    }
                    let (name, value) = match member.split_once('=') {
                        Some((n, v)) => (n.trim(), Some(v.trim())),
                        None => (member, None),
                    };
                    let lname = name.to_ascii_lowercase();

                    // `immutable` is the RFC 8246 §2 Cache-Control extension: it tells clients the
                    // origin will not update the representation during the response's freshness
                    // lifetime. (Its defining sentence resists machine extraction from the RFC HTML,
                    // so the two §2 cites on the violation below — its freshness-window behaviour —
                    // carry the spec reference for this rule.)
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
                return Some(self.violation(ctx.severity, format!(
                        "Cache-Control pairs 'immutable' with '{}', which leaves the response no freshness lifetime; 'immutable' only applies during one, so it has no effect here",
                        conflict
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Immutable Requires Freshness")
    }

    fn description(&self) -> &'static str {
        "This rule flags responses whose `Cache-Control` header pairs `immutable` with a directive that nullifies its fresh-window promise — `no-store` (nothing is stored), `no-cache` (reuse always requires revalidation), `max-age=0`, or `s-maxage=0` (zero freshness lifetime, the latter for shared caches). Per RFC 8246, `immutable` only applies during a stored response's freshness lifetime: it tells clients the representation will not change while the response is fresh, and asks them not to revalidate during that window. A response that can never be fresh has no such window, so `immutable` has nothing to act on, and one of the two directives is a mistake.\n\nNote: `immutable` together with `must-revalidate` is **not** flagged. Those directives govern disjoint windows — `immutable` applies while the response is fresh, `must-revalidate` binds once it has gone stale — and RFC 8246 says stale responses \"SHOULD be revalidated as they normally would be in the absence of the immutable extension\". `Cache-Control: max-age=3600, immutable, must-revalidate` is coherent. An earlier version of this rule (`server_must_revalidate_and_immutable_mismatch`) reported that pairing as an error. It was wrong: no sentence in RFC 9111 or RFC 8246 supported it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_8246_2, RFC_9111_5_2_2]
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
static REGISTRATION: &dyn crate::rules::Rule = &ImmutableRequiresFreshness;

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
        let rule = ImmutableRequiresFreshness;

        let tx = match cc {
            Some(v) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cache-control", v)],
            ),
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let cfg = crate::test_helpers::make_test_config_with_severity(
            "immutable_requires_freshness",
            "warn",
        );

        let v = crate::test_helpers::run_rule(
            &rule,
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

        let rule = ImmutableRequiresFreshness;
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "immutable_requires_freshness",
            "warn",
        );

        let v = crate::test_helpers::run_rule(
            &rule,
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

        let rule = ImmutableRequiresFreshness;
        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = ImmutableRequiresFreshness;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ImmutableRequiresFreshness;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert(rule.id().to_string(), toml::Value::Table(table));
        rule.prepare(&cfg)?;
        Ok(())
    }
}
