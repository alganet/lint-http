// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_MISSING, RFC_9111_4_2_2};
use crate::violations::ViolationDef;

/// One entry: a lifetime left to be guessed, separately, by every cache.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_MISSING];

pub struct CacheControlPresent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2",
    note: "Cache-Control — the header whose absence the rule reports",
};

impl RuleMeta for CacheControlPresent {
    fn id(&self) -> &'static str {
        "cache_control_present"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Cache-Control Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if `200 OK` responses include a `Cache-Control` header.\n\nThe `Cache-Control` header is the primary mechanism for defining the caching policies of a resource. Even if a resource should not be cached, it is best practice to explicitly state this (e.g., `Cache-Control: no-store`) rather than relying on default browser behaviors or heuristic caching."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_4_2_2, RFC_9111_5_2]
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
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/json\nCache-Control: no-store",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response with no Cache-Control field line"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/json",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(OPTIONS — \u{a7}9.3.7: no cache stores it, so none guesses at it)"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nAllow: GET, HEAD, OPTIONS\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(POST — \u{a7}9.3.3 gives a POST response no heuristic to take away)",
                ),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n",
            },
        ]
    }
}

impl Rule for CacheControlPresent {
    fn needs_response(&self) -> bool {
        // Server: the heuristic-freshness concern is about what an origin's response
        // does or does not tell caches, so only responses are inspected.
        true
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
            if let Some(resp) = &tx.response {
                // The heuristic this rule warns about is one a cache assigns to a
                // response it has stored, so the question comes after storability
                // rather than instead of it. RFC 9111 § 3 is a conjunction whose
                // first term is the request method, and § 9.2.3 names the three
                // methods that define caching semantics at all: an `OPTIONS` or a
                // `TRACE` answered `200` leaves nothing stored however it is
                // framed, so no `Cache-Control` its sender could add would take
                // any guess away from any cache. `POST` is on § 9.2.3's list and
                // is still refused here, by § 9.3.3 rather than by § 9.2.3: a POST
                // response is cacheable only with explicit freshness, so the
                // heuristic branch this rule is about is one it never reaches.
                // `response_is_storable` answers both, and the trigger below —
                // no `Cache-Control` at all — leaves it reading exactly the method
                // and the request's own `no-store`.
                // cite(RFC 9110 § 9.3.7): "Responses to the OPTIONS method are not cacheable."
                if !crate::helpers::stored_response::response_is_storable(
                    &tx.request.method,
                    &tx.request.headers,
                    resp.status,
                    &resp.headers,
                ) {
                    return None;
                }

                // Nothing requires a `Cache-Control` on a 200. What the absence of one buys is
                // a cache guessing: with no explicit expiration time, a heuristic freshness
                // lifetime is permitted, and the origin no longer decides how long its response
                // is reused. This rule asks servers to decide. It is advice, and cites the
                // sentence that makes it advice worth taking.
                // cite(RFC 9111 § 4.2.2): "Since origin servers do not always provide explicit expiration times, a cache MAY assign a heuristic expiration time when an explicit time is not specified, employing algorithms that use other field values (such as the Last-Modified time) to estimate a plausible expiration time."
                //
                // Scoped to 200 by choice, not by the spec. §4.2.2 permits heuristics on any
                // status "defined as heuristically cacheable (e.g., see Section 15.1 of
                // [HTTP])" — 203, 204, 206, 300, 301, 308, 404, 410, 451 among them — so the
                // same advice applies to those too. 200 is the overwhelmingly common case and
                // the least noisy to flag; widening the set is a behavior change, left out.
                if resp.status == 200 && !resp.headers.contains_key("cache-control") {
                    return Some(ctx.report(&CACHE_CONTROL_MISSING));
                }
            }
            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// The method is a parameter because RFC 9111 \u{a7} 3's conjunction opens with
    /// it: the heuristic this rule warns about is assigned to a stored
    /// response, and `OPTIONS`, `TRACE` and the rest of \u{a7} 9.2.3's absentees
    /// leave none. `POST` is on \u{a7} 9.2.3's list and is still not asked, by
    /// \u{a7} 9.3.3 — which is the one row here that differs from
    /// `status_and_caching_semantics` next door, so it is pinned in both files.
    #[rstest]
    #[case(
        "GET",
        200,
        None,
        true,
        Some("Response 200 without Cache-Control header")
    )]
    #[case(
        "HEAD",
        200,
        None,
        true,
        Some("Response 200 without Cache-Control header")
    )]
    #[case("GET", 200, Some(("cache-control", "no-cache")), false, None)]
    #[case("GET", 404, None, false, None)]
    #[case("OPTIONS", 200, None, false, None)]
    #[case("TRACE", 200, None, false, None)]
    #[case("POST", 200, None, false, None)]
    #[case("PUT", 200, None, false, None)]
    #[case("DELETE", 200, None, false, None)]
    fn check_response_cases(
        #[case] method: &str,
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = CacheControlPresent;

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = match header {
            Some((k, v)) => make_test_transaction_with_response(status, &[(k, v)]),
            None => make_test_transaction_with_response(status, &[]),
        };
        tx.request.method = method.to_string();
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            // Both of this subject's "said nothing" entries default to `info`:
            // nothing is broken, and what the finding reports is which of the two
            // opposite outcomes the silence bought.
            let found = violation.clone().expect("a finding");
            assert_eq!(found.violation, "cache_control_missing");
            assert_eq!(found.severity, crate::lint::Severity::Info);
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = CacheControlPresent;
        assert!(rule.needs_response());
    }

    /// Each example is a response, and the guard says so rather than assuming
    /// it: the start line supplies the status the rule gates on, so a
    /// request-shaped example would be judged against a status it never
    /// declared. The `NonCompliant` example used to carry `# Missing
    /// Cache-Control header` as a third line — published in the docs inside an
    /// `http` block as though a comment were a field line, and reaching no
    /// parser that could say otherwise.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = CacheControlPresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            // An example may open with a request line, and two of them do: the
            // method is what this rule reads first, so a guard that dropped the
            // line would judge an `OPTIONS` story as the `GET` the builder
            // defaults to and call a Compliant example a finding.
            let mut lines = ex.snippet.lines().peekable();
            let mut method = "GET".to_string();
            if lines
                .peek()
                .is_some_and(|l| !l.starts_with("HTTP/") && l.contains(" HTTP/"))
            {
                let request_line = lines.next().expect("peeked");
                method = request_line
                    .split_whitespace()
                    .next()
                    .expect("a request line has a method")
                    .to_string();
                // Then the request's own field lines, up to the blank line that
                // separates the two messages.
                for l in lines.by_ref() {
                    if l.trim().is_empty() {
                        break;
                    }
                }
            }
            let start = lines.next().expect("an example has a start line");
            let status: u16 = start
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {start:?}"));
            let pairs: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
            tx.request.method.clone_from(&method);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );

            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
