// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Detect obvious contradictions in Cache-Control directives. Flagged:
/// - `public` and `private` present simultaneously (contradictory visibility)
/// - `no-store` combined with `public` or `private` (no-store forbids storing)
/// - multiple `max-age` or `s-maxage` directives with differing values
/// - an empty list element (RFC 9110 §5.6.1.1)
///
/// `no-cache` with `max-age=0` is a legal, common combination and is intentionally NOT flagged.
pub struct CachingDirectiveInteraction;

impl Rule for CachingDirectiveInteraction {
    fn id(&self) -> &'static str {
        "caching_directive_interaction"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // Helper to check a single HeaderMap for contradictions
            let check_headers = |hdrs: &hyper::HeaderMap| -> Option<Violation> {
                use crate::helpers::headers::split_commas_respecting_quotes;

                // Collect directives across possibly multiple header fields
                let mut directives: Vec<(String, Option<String>)> = Vec::new();

                for hv in hdrs.get_all("cache-control").iter() {
                    let s = match hv.to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            return Some(self.violation(
                                ctx.severity,
                                "Cache-Control header contains non-UTF8 value".into(),
                            ))
                        }
                    };

                    // An entirely empty Cache-Control value is a zero-element list, which is legal
                    // (`#element => [ 1#element ]`); that is distinct from an empty *element*
                    // within a list, which the check below flags. Skip the empty-list case.
                    if s.trim().is_empty() {
                        continue;
                    }

                    for member in split_commas_respecting_quotes(s) {
                        let m = member;
                        if m.is_empty() {
                            // Cache-Control is a `#cache-directive` list, and the sender (client on a
                            // request, server on a response) must not emit empty list elements.
                            // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                            return Some(self.violation(
                                ctx.severity,
                                "Cache-Control header contains empty member".into(),
                            ));
                        }

                        let mut kv = m.splitn(2, '=');
                        let name = kv.next().unwrap().trim().to_ascii_lowercase();
                        let value = kv.next().map(|v| v.trim().to_string());

                        directives.push((name, value));
                    }
                }

                if directives.is_empty() {
                    return None;
                }

                use std::collections::HashMap;
                let mut seen: HashMap<String, Vec<Option<String>>> = HashMap::new();
                for (n, v) in directives {
                    seen.entry(n).or_default().push(v);
                }

                // public vs private contradiction. Only *unqualified* private (no `=field-name`
                // argument) forbids a shared cache from storing the whole response; qualified
                // `private="…"` lets it store the rest, so it does not contradict public — the cite
                // is explicitly about "unqualified private". For a shared cache the unqualified
                // pair directly conflicts: public says it MAY store, private says it MUST NOT. The
                // spec resolves conflicting directives by honoring the most restrictive (§4.2.1),
                // so this flag is a misconfiguration heuristic, not an illegal combination.
                // cite(RFC 9111 § 5.2.2.9): "The public response directive indicates that a cache MAY store the response even if it would otherwise be prohibited, subject to the constraints defined in Section 3."
                // cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
                let private_unqualified = seen
                    .get("private")
                    .is_some_and(|vs| vs.iter().any(|v| v.is_none()));
                if seen.contains_key("public") && private_unqualified {
                    return Some(self.violation(ctx.severity, "Cache-Control contains both 'public' and 'private' directives (contradictory visibility)".into()));
                }

                // no-store with public/private
                if seen.contains_key("no-store")
                    && (seen.contains_key("public") || seen.contains_key("private"))
                {
                    // `no-store` forbids storing at all, so pairing it with a directive whose
                    // only job is to say *which* caches may store is a contradiction: one of
                    // the two is dead text, and the server does not know which it meant.
                    // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
                    return Some(self.violation(ctx.severity, "Cache-Control contains 'no-store' together with 'public' or 'private' (contradiction)".into()));
                }

                // Note: combinations like 'no-cache' with 'max-age=0' are allowed per RFC 9111 §3
                // and are intentionally *not* flagged as redundant by this rule.

                // Multiple max-age or s-maxage with differing values is ambiguous; the spec says a
                // cache should use the first occurrence or treat the response as stale, so flagging
                // the divergence is a consistency heuristic.
                // cite(RFC 9111 § 4.2.1): "When there is more than one value present for a given directive (e.g., two Expires header field lines or multiple Cache-Control: max-age directives), either the first occurrence should be used or the response should be considered stale."
                for key in ["max-age", "s-maxage"] {
                    if let Some(vals) = seen.get(key) {
                        // Collect numeric values (unquoted token form) and compare
                        let mut nums: Vec<String> = Vec::new();
                        for s in vals.iter().flatten() {
                            let s = s.trim();
                            let inner = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                                &s[1..s.len() - 1]
                            } else {
                                s
                            };
                            if !inner.is_empty() {
                                nums.push(inner.to_string());
                            }
                        }
                        if nums.len() > 1 {
                            // if at least two are different, flag
                            let first = &nums[0];
                            if nums.iter().any(|x| x != first) {
                                return Some(self.violation(ctx.severity, format!("Cache-Control contains multiple '{}' directives with differing values", key)));
                            }
                        }
                    }
                }

                None
            };

            // Check request and response headers
            if let Some(v) = check_headers(&tx.request.headers) {
                return Some(v);
            }
            if let Some(resp) = &tx.response {
                if let Some(v) = check_headers(&resp.headers) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Detect contradictions in `Cache-Control` directives that affect caching semantics: `public` and `private` together (contradictory visibility), `no-store` with `public`/`private`, differing repeated `max-age`/`s-maxage` values, and empty list elements. `no-cache` together with `max-age=0` is a legal combination and is not flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2",
                note: "Response directives: public (§5.2.2.9), private (§5.2.2.7), no-store (§5.2.2.5), max-age/s-maxage",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1",
                note: "Conflicting directives are resolved by the most restrictive; multiple values for a directive → first or stale",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
                note: "List (`#rule`) syntax: a sender MUST NOT generate empty list elements",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Cache-Control: public, max-age=3600",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Cache-Control: public, private\n\nCache-Control: no-store, public\n\nCache-Control: max-age=60, max-age=30",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CachingDirectiveInteraction;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(cc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("cache-control", cc)]);
        tx
    }

    fn make_resp(cc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", cc)]);
        tx
    }

    #[rstest]
    #[case("public, max-age=3600", false)]
    #[case("public, private", true)]
    #[case("no-store, public", true)]
    #[case("no-cache, max-age=0", false)]
    #[case("no-cache, max-age=60", false)]
    #[case("max-age=60, max-age=60", false)]
    #[case("max-age=60, max-age=30", true)]
    #[case("s-maxage=60, s-maxage=60", false)]
    #[case("s-maxage=60, s-maxage=30", true)]
    // Qualified `private="field"` lets a shared cache store the rest, so `public` + qualified
    // private is not a contradiction (only *unqualified* private is).
    #[case("public, private=\"Set-Cookie\"", false)]
    // An entirely empty Cache-Control value is a legal zero-element list, not an empty element.
    #[case("", false)]
    fn request_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let rule = CachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let tx = make_req(val);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", val);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", val, v);
        }
    }

    #[rstest]
    #[case("public, max-age=3600", false)]
    #[case("public, private", true)]
    #[case("no-store, public", true)]
    #[case("no-cache, max-age=0", false)]
    #[case("max-age=60, max-age=60", false)]
    #[case("s-maxage=60, s-maxage=30", true)]
    fn response_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let rule = CachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let tx = make_resp(val);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", val);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", val, v);
        }
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.request.headers = hm;
        let rule = CachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_member_is_violation() {
        let rule = CachingDirectiveInteraction;
        let tx = make_req(",max-age=1");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_max_age_zero_no_violation() {
        let rule = CachingDirectiveInteraction;
        let tx = make_req("no-cache, max-age=\"0\"");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_combined_reports_violation() {
        use hyper::header::HeaderValue;
        let rule = CachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append("cache-control", HeaderValue::from_static("no-store"));
        hm.append("cache-control", HeaderValue::from_static("public"));
        tx.request.headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn conflicting_max_age_values_reports_violation() {
        let rule = CachingDirectiveInteraction;
        let tx = make_req("max-age=60, max-age=\"30\"");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn no_cache_control_header_no_violation() {
        let rule = CachingDirectiveInteraction;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "caching_directive_interaction");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "caching_directive_interaction");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("caching_directive_interaction")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
