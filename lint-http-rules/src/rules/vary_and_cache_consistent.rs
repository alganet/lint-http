// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_REDUNDANT, RFC_9111_4_1};
use crate::violations::ViolationDef;

/// One entry, and it is on the field that is dead: a directive advertising
/// reuse beside a `Vary` no stored response can match.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_REDUNDANT];

/// Responses that include `Vary: *` cannot be selected by caches for
/// subsequent requests (a `Vary: *` always fails to match; see RFC 9111 §4.1).
/// If a response also advertises explicit cacheability directives such as
/// `Cache-Control: max-age`/`s-maxage` or `public`, those directives are
/// likely ineffective because caches cannot select stored responses when
/// `Vary: *` is present. This rule flags those cases as likely misconfiguration.
pub struct VaryAndCacheConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3",
    note: "Storing Responses in Caches (cacheability requirements)",
};

impl RuleMeta for VaryAndCacheConsistent {
    fn id(&self) -> &'static str {
        "vary_and_cache_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Vary and Cache Consistency")
    }

    fn description(&self) -> &'static str {
        "When a response includes `Vary: *`, caches cannot select that stored response for subsequent requests (a `Vary: *` always fails to match). If the same response advertises explicit cacheability directives (such as `Cache-Control: max-age`/`s-maxage` or `public`), those directives are likely ineffective for reuse by caches. This rule flags cases where `Vary: *` and explicit cacheability directives are both present."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_4_1, RFC_9111_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nVary: Accept-Encoding\nCache-Control: max-age=3600\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nVary: *\nCache-Control: max-age=3600\n\n<response body>",
            },
        ]
    }
}

impl Rule for VaryAndCacheConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // The two verdicts about the response as a whole end the reading; the
        // walk over the directives answers per directive and collects.
        let finding = || -> Vec<Violation> {
            let Some(resp) = tx.response.as_ref() else {
                return Vec::new();
            };

            // A `Vary: *` can never be matched by a cache, so any explicit
            // cacheability directive on the same response is ineffective.
            //
            // The walk this replaced read the field lines one at a time and returned
            // no finding at all when `to_str` refused one — so a single `obs-text`
            // octet anywhere in the value stood the rule down — and it did not join
            // them, so a `*` written on a second field line was not a `*` here while
            // it was one to `prefer_header_and_preference_applied`. Both are
            // `helpers::headers::vary_nomination`'s answer now, for all three rules
            // that ask.
            //
            // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
            if !crate::helpers::vary::vary_nomination(&resp.headers).is_wildcard() {
                return Vec::new();
            }

            // If Vary: * is present, an explicit cacheability directive is likely ineffective (the
            // response can never be selected). No sentence says this pairing is illegal, so this is
            // a misconfiguration heuristic, recorded in the tracker.
            // Only directives that *advertise reuse* are flagged. `no-cache` is
            // deliberately excluded: it promises no reuse benefit (it requires
            // revalidation), so pairing it with Vary: * is not a misconfiguration signal.
            const ADVERTISES_REUSE: [&str; 3] = ["max-age", "s-maxage", "public"];
            // The joined value is held here because a directive borrows the
            // member it was parsed from, and it is read as octets so a bad
            // one no longer hides the directives written beside it.
            let lines = crate::helpers::cache_control::field_lines(&resp.headers);
            // `Cache-Control = #cache-directive`, and each directive that
            // advertises reuse is a separate thing this response says and this
            // `Vary` makes ineffective: an operator removing `max-age` has not
            // dealt with the `s-maxage` written beside it. The finding names the
            // directive, so the two sentences differ.
            let mut out = Vec::new();
            for directive in crate::helpers::cache_control::directives_in(&lines) {
                if ADVERTISES_REUSE.iter().any(|name| directive.is(name)) {
                    let name = directive.name.to_ascii_lowercase();
                    out.push(ctx.report_with(&CACHE_CONTROL_REDUNDANT, format!(
                            "Response includes Vary: '*' and Cache-Control directive '{}'; Vary: '*' prevents caches from selecting stored responses, making cache directives like '{}' ineffective",
                            name, name
                        )));
                }
            }

            out
        };
        finding()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryAndCacheConsistent;

#[cfg(test)]
mod tests {
    /// The cases below are responses stating one defect, and this says so
    /// rather than taking the first of however many were reported: `run_rule`
    /// is `run_rule_all(..).into_iter().next()`, so a walk that starts
    /// answering twice passes every one-defect case already written here.
    fn one_finding(
        rule: &dyn crate::rules::Rule,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<crate::lint::Violation> {
        let mut found = crate::test_helpers::run_rule_all(rule, tx, history, cfg);
        assert!(
            found.len() <= 1,
            "this fixture is for responses stating one defect; got {:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        found.pop()
    }

    use super::*;
    use rstest::rstest;

    /// The one entry, and it is on the field the pairing kills: a directive
    /// advertising reuse that no cache can act on, because the wildcard beside
    /// it never matches.
    #[test]
    fn the_finding_names_the_entry_of_the_field_that_is_dead() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "*"), ("cache-control", "max-age=86400")],
        );
        let found = one_finding(
            &VaryAndCacheConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "vary_and_cache_consistent",
            ]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "cache_control_redundant");
        assert_eq!(found.severity, crate::lint::Severity::Warn);
    }

    fn make_tx(vary: Option<&str>, cc: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = vary {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("vary", v)]);
            if let Some(c) = cc {
                tx.response
                    .as_mut()
                    .unwrap()
                    .headers
                    .append("cache-control", c.parse().unwrap());
            }
        } else if let Some(c) = cc {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("cache-control", c)]);
        }
        tx
    }

    #[rstest]
    // The count is the expectation and not a `bool`: `public, max-age=60`
    // names two directives the wildcard kills, and each is a separate thing to
    // remove. A `bool` here read "at least one finding", which is exactly what
    // a walk answering once about a list also satisfies.
    #[case(Some("*"), Some("max-age=3600"), 1)]
    #[case(Some("*"), Some("s-maxage=3600"), 1)]
    #[case(Some("*"), Some("public"), 1)]
    #[case(Some("*"), Some("public, max-age=60"), 2)]
    #[case(Some("*"), Some("no-cache"), 0)]
    #[case(Some("Accept-Encoding"), Some("max-age=60"), 0)]
    #[case(None, Some("max-age=60"), 0)]
    fn check_cases(#[case] vary: Option<&str>, #[case] cc: Option<&str>, #[case] expected: usize) {
        let rule = VaryAndCacheConsistent;
        let tx = make_tx(vary, cc);
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            found.len(),
            expected,
            "vary={:?}, cc={:?}: {:?}",
            vary,
            cc,
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// The two ways the walk this rule used to hold could not see a `*`.
    #[test]
    fn the_star_is_found_across_the_fields_lines_and_past_an_obs_text_octet() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge = |vary: &[&[u8]]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            let headers = &mut tx.response.as_mut().expect("a response").headers;
            for line in vary {
                headers.append(
                    HeaderName::from_static("vary"),
                    HeaderValue::from_bytes(line).expect("a test Vary value"),
                );
            }
            headers.append(
                "cache-control",
                "max-age=3600".parse().expect("a directive"),
            );
            one_finding(
                &VaryAndCacheConsistent,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "vary_and_cache_consistent",
                ]),
            )
        };

        // §5.3 makes the lines one value and `#( "*" / field-name )` is what
        // licenses the join, so this `*` is a member. Read line by line it was
        // not one.
        assert!(judge(&[b"accept-encoding", b"*"]).is_some());
        // `to_str` refuses %xE9, and refusing it used to end the rule — so a
        // `*` beside an `obs-text` octet drew nothing at all.
        assert!(judge(&[b"caf\xe9, *"]).is_some());
        assert!(judge(&[b"caf\xe9", b"*"]).is_some());
        // And an `obs-text` octet on its own still nominates no `*`.
        assert!(judge(&[b"caf\xe9"]).is_none());
    }

    #[test]
    fn non_utf8_cache_control_ignored() {
        // non-utf8 cache-control should not panic the rule
        use hyper::header::HeaderValue;
        let rule = VaryAndCacheConsistent;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("vary", "*")]);
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("cache-control", bad);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = VaryAndCacheConsistent;
        assert_eq!(rule.id(), "vary_and_cache_consistent");
        assert!(rule.needs_response());
    }

    #[test]
    fn vary_star_across_multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryAndCacheConsistent;

        // Vary: Accept-Encoding and Vary: * across header fields, plus Cache-Control: max-age
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("vary", HeaderValue::from_static("Accept-Encoding"));
        hm.append("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn cache_control_case_insensitive_directive_detection() {
        let rule = VaryAndCacheConsistent;

        // Public (mixed case) should be detected
        let tx = make_tx(Some("*"), Some("Public"));
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());

        // MAX-AGE uppercase
        let tx2 = make_tx(Some("*"), Some("MAX-AGE=60"));
        let v2 = one_finding(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_some());
    }

    #[test]
    fn multiple_cache_control_headers_with_max_age_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryAndCacheConsistent;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("no-cache"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn extension_directive_only_is_not_a_violation() {
        // Vary: * with a non-cacheability extension should not be flagged
        let rule = VaryAndCacheConsistent;
        let tx = make_tx(Some("*"), Some("foo=bar"));
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = VaryAndCacheConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "vary_and_cache_consistent",
        ]);
        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }

    /// Each directive advertising reuse is a separate thing this response says
    /// and this `Vary` makes ineffective, so removing `max-age` has not dealt
    /// with the `s-maxage` written beside it. The finding names the directive.
    #[test]
    fn every_reuse_directive_the_wildcard_kills_is_named() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "*"), ("cache-control", "max-age=60, s-maxage=60")],
        );
        let found = crate::test_helpers::run_rule_all(
            &VaryAndCacheConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "vary_and_cache_consistent",
            ]),
        );
        let messages: Vec<&str> = found.iter().map(|v| v.message.as_str()).collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages[0].contains("'max-age'"), "{messages:?}");
        assert!(messages[1].contains("'s-maxage'"), "{messages:?}");
    }
}
