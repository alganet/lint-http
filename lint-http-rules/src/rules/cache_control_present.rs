// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct CacheControlPresent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_4_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2",
    note: "Calculating Heuristic Freshness — without an explicit expiration time a cache MAY guess one, which is what this rule asks the origin to avoid",
};
const RFC_9111_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2",
    note: "Cache-Control — the header whose absence the rule reports",
};

impl Rule for CacheControlPresent {
    fn id(&self) -> &'static str {
        "cache_control_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // Server: the heuristic-freshness concern is about what an origin's response
        // does or does not tell caches, so only responses are inspected.
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
            if let Some(resp) = &tx.response {
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
                    return Some(self.violation(
                        ctx.severity,
                        "Response 200 without Cache-Control header".into(),
                    ));
                }
            }
            None
        };
        Vec::from_iter(finding())
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
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(200, None, true, Some("Response 200 without Cache-Control header"))]
    #[case(200, Some(("cache-control", "no-cache")), false, None)]
    #[case(404, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = CacheControlPresent;

        use crate::test_helpers::make_test_transaction_with_response;
        let tx = match header {
            Some((k, v)) => make_test_transaction_with_response(status, &[(k, v)]),
            None => make_test_transaction_with_response(status, &[]),
        };
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
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
    fn scope_is_server() {
        let rule = CacheControlPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
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
        use crate::rules::{Compliance, Rule as _};
        let rule = CacheControlPresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
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

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
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
