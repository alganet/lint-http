// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_FRESHNESS_MISSING, RFC_9110_15_1};
use crate::violations::ViolationDef;

/// One entry: a status no cache stores by default, saying nothing about how
/// long it would be good for.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_FRESHNESS_MISSING];

/// Ensures responses that are not cacheable by default include explicit
/// freshness information (e.g., `Cache-Control: max-age=...` / `s-maxage=...` or `Expires`).
/// Default-cacheable status codes are: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501.
pub struct StatusAndCachingSemantics;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3",
    note: "Storing Responses in Caches (the freshness signals a cache requires: Expires, max-age, s-maxage, or a heuristically cacheable status)",
};

impl RuleMeta for StatusAndCachingSemantics {
    fn id(&self) -> &'static str {
        "status_and_caching_semantics"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Status and Caching Semantics")
    }

    fn description(&self) -> &'static str {
        "Responses with certain status codes are cacheable by default (for example: `200`, `203`, `204`, `206`, `300`, `301`, `308`, `404`, `405`, `410`, `414`, `501`). For other status codes to be cacheable, servers MUST include explicit freshness information such as `Cache-Control: max-age=<seconds>` / `Cache-Control: s-maxage=<seconds>` or an `Expires` header.\n\nThis rule warns when a response status that is not cacheable by default does not include explicit freshness information."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_3, RFC_9110_15_1]
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
                snippet:
                    "HTTP/1.1 302 Found\nCache-Control: max-age=60\nLocation: https://example.org/",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 503 Service Unavailable\nExpires: Wed, 21 Oct 2015 07:28:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.org/",
            },
        ]
    }
}

impl Rule for StatusAndCachingSemantics {
    fn needs_response(&self) -> bool {
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
            let resp = tx.response.as_ref()?;

            let status = resp.status;

            // An interim response is not stored at any freshness it states.
            // Storability is a conjunction, and § 3 puts a final status code
            // ahead of the freshness condition this rule reads: a 1xx fails the
            // earlier one, so no `max-age` a sender could add would make a cache
            // hold it. Asking it for freshness names a fix that does not exist
            // — every WebSocket handshake in the corpus drew this finding, and
            // the 101 it drew it on is the one response no cache was ever going
            // to store.
            // cite(RFC 9111 § 3): "the response status code is final"
            if (100..200).contains(&status) {
                return None;
            }

            // The heuristically cacheable status codes (RFC 9111 §4.2.2 calls the older name
            // "cacheable by default"), enumerated in RFC 9110 §15.1. Such a response can be reused
            // with heuristic expiration, so it needs no explicit freshness.
            // cite(RFC 9110 § 15.1): "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"
            if crate::helpers::status::is_heuristically_cacheable(status) {
                return None;
            }

            // Helper: check Cache-Control directives for explicit freshness (max-age or s-maxage)
            // A present max-age or s-maxage is explicit freshness that makes the
            // response storable (RFC 9111 §3), so there is nothing to report. The
            // helper answers with the first non-negative delta-seconds given for
            // the directive, which is exactly this question.
            // cite(RFC 9111 § 5.2.2.1): "The max-age response directive indicates that the response is to be considered stale after its age is greater than the specified number of seconds."
            // cite(RFC 9111 § 5.2.2.10): "The s-maxage response directive indicates that, for a shared cache, the maximum age specified by this directive overrides the maximum age specified by either the max-age directive or the Expires"
            let advertises_freshness = ["max-age", "s-maxage"].iter().any(|directive| {
                crate::helpers::cache_control::delta_seconds(&resp.headers, directive).is_some()
            });
            if advertises_freshness {
                return None;
            }

            // A present, well-formed Expires is explicit freshness. Note this is stricter than
            // §3, which counts the mere presence of an Expires field: a malformed date is treated
            // here as no freshness (it establishes none), a deliberate hygiene choice.
            // cite(RFC 9111 § 5.3): "The "Expires" response header field gives the date/time after which the response is considered stale."
            if let Some(hv) = resp.headers.get_all("expires").iter().next() {
                if let Ok(s) = hv.to_str() {
                    if crate::http_date::is_valid_http_date(s.trim()) {
                        return None;
                    }
                }
            }

            // None of the storability signals §3 requires are present, and the status is not
            // heuristically cacheable — so a cache cannot store this response.
            // cite(RFC 9111 § 3): "A cache MUST NOT store a response to a request unless"
            Some(ctx.report_with(&CACHE_CONTROL_FRESHNESS_MISSING, format!(
                    "Response {} is not cacheable by default and lacks explicit freshness information (Cache-Control: max-age/s-maxage or Expires)",
                    status
                )))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatusAndCachingSemantics;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(302, vec![], true)]
    #[case(302, vec![("cache-control", "max-age=60")], false)]
    #[case(302, vec![("cache-control", "s-maxage=10")], false)]
    #[case(302, vec![("cache-control", "max-age=-1")], true)]
    #[case(302, vec![("cache-control", "max-age=abc")], true)]
    #[case(302, vec![("cache-control", "public"), ("cache-control", "max-age=5")], false)]
    #[case(503, vec![("expires", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case(503, vec![("expires", "not-a-date")], true)]
    #[case(200, vec![], false)] // 200 is cacheable by default
    #[case(308, vec![], false)]
    // 308 is heuristically cacheable (RFC 9110 §15.1), no freshness needed
    // An interim response is never stored, so the freshness question does not
    // apply to it — not even when it states freshness, which is why the 101
    // carrying `max-age` is here beside the one that carries nothing.
    #[case(101, vec![], false)]
    #[case(101, vec![("cache-control", "max-age=60")], false)]
    #[case(100, vec![], false)]
    #[case(103, vec![], false)]
    // The neighbouring class stays asked: a 5xx is final, and § 3 lets a cache
    // store one that states its own freshness. The rule's own compliant example
    // is a 503 with an `Expires`.
    #[case(503, vec![], true)]
    fn caching_cases(
        #[case] status: u16,
        #[case] hdrs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = StatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(status, &hdrs);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for status {} headers={:?}",
                status,
                hdrs
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
        Ok(())
    }

    #[test]
    fn non_utf8_cache_control_is_ignored() -> anyhow::Result<()> {
        let rule = StatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = make_test_transaction_with_response(302, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("cache-control", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Both of this subject's "said nothing" entries default to `info`:
        // nothing is broken, and what the finding reports is which of the two
        // opposite outcomes the silence bought.
        let found = v.expect("a finding");
        assert_eq!(found.violation, "cache_control_freshness_missing");
        assert_eq!(found.severity, crate::lint::Severity::Info);
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "status_and_caching_semantics");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = StatusAndCachingSemantics;
        assert!(rule.needs_response());
    }
}
