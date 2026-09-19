// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{
    CACHE_CONTROL_FRESHNESS_CONFLICTING, CACHE_CONTROL_STORAGE_CONFLICTING, RFC_9111_4_2_1,
    RFC_9111_5_2_2_5, RFC_9111_5_2_2_7, RFC_9111_5_2_2_9,
};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::ViolationDef;

/// Three entries, and only two of them are this field's own.
///
/// A member written blank is the list construct's defect, reported here with
/// the id twenty other `#`-list fields report it with — this rule reads the
/// raw members precisely so it can see one, since the directive walk drops it.
/// What is left are two disagreements: about whether the response may be
/// stored, and about how long it stays fresh.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_EMPTY,
    &CACHE_CONTROL_STORAGE_CONFLICTING,
    &CACHE_CONTROL_FRESHNESS_CONFLICTING,
];

/// Detect obvious contradictions in Cache-Control directives. Flagged:
/// - `public` and `private` present simultaneously (contradictory visibility)
/// - `no-store` combined with `public` (public grants what no-store forbids)
/// - multiple `max-age` or `s-maxage` directives with differing values
/// - an empty list element (RFC 9110 §5.6.1.1)
///
/// `no-cache` with `max-age=0`, and `private` with `no-store`, are legal, common
/// combinations in which one directive is contained in the other; neither is flagged.
pub struct CachingDirectiveInteraction;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2",
    note: "Response directives: public (§5.2.2.9), private (§5.2.2.7), no-store (§5.2.2.5), max-age/s-maxage",
};

impl RuleMeta for CachingDirectiveInteraction {
    fn id(&self) -> &'static str {
        "caching_directive_interaction"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Detect contradictions in `Cache-Control` directives that affect caching semantics: `public` and `private` together (contradictory visibility), `no-store` with `public`, differing repeated `max-age`/`s-maxage` values, and empty list elements. `no-cache` together with `max-age=0`, and `private` together with `no-store`, are legal combinations in which one directive is contained in the other, and are not flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_2_2,
            RFC_9111_5_2_2_5,
            RFC_9111_5_2_2_7,
            RFC_9111_5_2_2_9,
            RFC_9111_4_2_1,
            RFC_9110_5_6_1_1,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **The conflicts this reads are between directives inside one field
    /// section**, never across the two, so the answer is the section: a request
    /// carrying contradictory `Cache-Control` directives is the client's defect
    /// and a response carrying them is the origin's.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
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
                compliance: Compliance::Compliant,
                label: Some("(`private` is contained in `no-store`; the pair agrees)"),
                snippet: "Cache-Control: private, no-store",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Cache-Control: public, private\nCache-Control: no-store, public\nCache-Control: max-age=60, max-age=30",
            },
        ]
    }
}

impl Rule for CachingDirectiveInteraction {
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
            let check_headers = |hdrs: &hyper::HeaderMap,
                                 party: crate::lint::Party|
             -> Option<Violation> {
                // The value is read as the octets the sender wrote, so there is
                // no line for a reader to skip and nothing for this rule to say
                // about the field's encoding. An octet no `tchar` admits is a
                // directive name's defect, which the two syntax rules next door
                // report with the id that names it.
                let lines = crate::helpers::cache_control::field_lines(hdrs);

                // An empty *element* within the list is forbidden — as distinct
                // from an entirely empty field value, which is a legal
                // zero-element list and which `members` already exempts.
                // `directives_of` would have dropped the empty member; this is
                // what the raw reader is for.
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                if crate::helpers::cache_control::members(&lines).any(str::is_empty) {
                    return Some(ctx.by(party).report_with(
                        &LIST_MEMBER_EMPTY,
                        "Cache-Control header contains empty member".into(),
                    ));
                }

                // Directive names are compared case-insensitively, so the map is
                // keyed by the folded name; the argument is kept as written.
                use std::collections::HashMap;
                let mut seen: HashMap<String, Vec<Option<String>>> = HashMap::new();
                for directive in crate::helpers::cache_control::directives_in(&lines) {
                    seen.entry(directive.name.to_ascii_lowercase())
                        .or_default()
                        .push(directive.argument.map(str::to_string));
                }

                if seen.is_empty() {
                    return None;
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
                    return Some(ctx.by(party).report_with(&CACHE_CONTROL_STORAGE_CONFLICTING, "Cache-Control contains both 'public' (RFC 9111 \u{a7}5.2.2.9) and an unqualified 'private' (\u{a7}5.2.2.7): a shared cache MAY store the response and MUST NOT store it".into()));
                }

                // `no-store` beside `public`. `public` grants storage to every cache
                // "even if it would otherwise be prohibited" and `no-store` prohibits it
                // to every cache; § 3 settles the response for `no-store`, so the grant
                // is dead text and the two directives say opposite things about one
                // response.
                //
                // `private` beside `no-store` is NOT this pair. `private` forbids the
                // shared caches what `no-store` forbids all of them, so the two agree
                // about storing and the weaker is contained in the stronger — the
                // relation `no-cache` and `max-age=0` have to `no-store`, which this
                // rule leaves alone on purpose. It is also the commonest way a response
                // says "do not cache this", and nothing in it is dead text a server
                // could have meant otherwise.
                // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
                if seen.contains_key("no-store") && seen.contains_key("public") {
                    return Some(ctx.by(party).report_with(&CACHE_CONTROL_STORAGE_CONFLICTING, "Cache-Control contains both 'no-store' (RFC 9111 \u{a7}5.2.2.5) and 'public' (\u{a7}5.2.2.9): every cache MUST NOT store the response and any cache MAY store it".into()));
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
                                return Some(ctx.by(party).report_with(&CACHE_CONTROL_FRESHNESS_CONFLICTING, format!("Cache-Control contains multiple '{}' directives with differing values, and RFC 9111 \u{a7}4.2.1 leaves a cache free to use the first or to treat the response as stale", key)));
                            }
                        }
                    }
                }

                None
            };

            // Check request and response headers
            if let Some(v) = check_headers(&tx.request.headers, crate::lint::Party::Client) {
                return Some(v);
            }
            if let Some(resp) = &tx.response {
                if let Some(v) = check_headers(&resp.headers, crate::lint::Party::Server) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
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

    /// The three findings and the ids they draw. The two storage rows are one
    /// entry because a sender deletes one directive either way and a cache
    /// honours the most restrictive either way; the empty member is not this
    /// field's defect at all.
    #[rstest]
    #[case(",max-age=1", "list_member_empty")]
    #[case("public, private", "cache_control_storage_conflicting")]
    #[case("no-store, public", "cache_control_storage_conflicting")]
    // `private` is contained in `no-store`: the pair agrees about storing.
    #[case("no-store, private", "")]
    #[case("private, max-age=0, no-store, no-cache, must-revalidate", "")]
    #[case("max-age=60, max-age=120", "cache_control_freshness_conflicting")]
    #[case("s-maxage=60, s-maxage=120", "cache_control_freshness_conflicting")]
    // A qualified `private` exempts named fields and lets a shared cache store
    // the rest, so it says nothing `public` disagrees with.
    #[case("public, private=\"Set-Cookie\"", "")]
    fn each_finding_names_its_entry(#[case] cc: &str, #[case] expected: &str) {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let found = crate::test_helpers::run_rule(
            &CachingDirectiveInteraction,
            &make_req(cc),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        match expected {
            "" => assert!(found.is_none(), "{cc:?}: {found:?}"),
            id => assert_eq!(found.expect("a finding").violation, id, "{cc:?}"),
        }
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
    #[case("no-store, private", false)]
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
    #[case("no-store, private", false)]
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

    /// The octet is not this rule's finding, and the directives written beside
    /// it are. The reader used to drop the whole field line, so the
    /// contradiction below was invisible and what this rule reported instead
    /// was a verdict about the field's encoding — a claim `cache_control_token_valid`
    /// and `cache_control_directive_valid` answer properly, with the id that
    /// names the octet.
    #[test]
    fn an_octet_hides_neither_the_contradiction_nor_this_rules_silence() {
        use hyper::header::HeaderValue;
        let rule = CachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "caching_directive_interaction",
        ]);
        let run = |bytes: &[u8]| {
            let mut tx = crate::test_helpers::make_test_transaction();
            let mut hm = hyper::HeaderMap::new();
            hm.insert(
                "cache-control",
                HeaderValue::from_bytes(bytes).expect("a line"),
            );
            tx.request.headers = hm;
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
        };

        assert!(run(&[0xff]).is_none(), "the octet alone is not this rule's");
        let found = run(b"public, private, \xff").expect("the contradiction");
        assert_eq!(found.violation, "cache_control_storage_conflicting");
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
}
