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

/// Ensures a response no cache stores by default says something that would
/// let one store it — explicit freshness (`Cache-Control: max-age=...` /
/// `s-maxage=...` or `Expires`), or the `public` or `private` directive that
/// licenses storage and lets § 4.2.2 supply the lifetime instead.
/// Default-cacheable status codes are: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501.
pub struct StatusAndCachingSemantics;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3",
    note: "Storing Responses in Caches (the licences to store a response: public, private, Expires, max-age, s-maxage, a cache extension, or a heuristically cacheable status)",
};

/// What a cache does with a `304`, which is the answer to whether one is a
/// response a cache stores at all.
const RFC_9111_4_3_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4",
    note: "Freshening Stored Responses upon Validation — a 304 updates the header fields of the stored responses it identifies; it is not itself a response a cache keeps",
};

/// The one section that states a sender's obligation about `Cache-Control` and
/// `Expires` on a `304`, and states it conditionally.
const RFC_9110_15_4_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
    note: "304 Not Modified — the fields a 304 MUST generate, Cache-Control and Expires among them, and only those the 200 to the same request would have carried",
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
        "Responses with certain status codes are heuristically cacheable (for example: `200`, `203`, `204`, `206`, `300`, `301`, `308`, `404`, `405`, `410`, `414`, `501`). A response on any other status is stored only if it says something that licenses storing it: explicit freshness (`Cache-Control: max-age=<seconds>` / `Cache-Control: s-maxage=<seconds>` or an `Expires` header), or a `public` or `private` directive — which licenses storage on its own and lets a cache calculate the lifetime heuristically.\n\nThis rule warns when a response status that is not heuristically cacheable says none of those, so no cache may keep it. It stays silent where a lifetime would not help: `no-store` on either message, an interim status, a method that defines no caching semantics, and a `304 (Not Modified)` — RFC 9111 §4.3.4 has a cache *update* stored responses from a 304 rather than keep the 304, and RFC 9110 §15.4.5 is the one sentence that asks a 304 for `Cache-Control` or `Expires`, conditionally on the `200` to the same request having carried one. That condition is `status_304_field_missing`'s to read."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_3, RFC_9110_15_1, RFC_9111_4_3_4, RFC_9110_15_4_5]
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
                compliance: Compliance::Compliant,
                label: Some(
                    "(`public` licenses storing it without a lifetime, and \u{a7}4.2.2 lets the cache calculate one)",
                ),
                snippet: "HTTP/1.1 302 Found\nCache-Control: public\nLocation: https://example.org/",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(`no-store` fails an earlier term of \u{a7}3, so no lifetime would make a cache keep it)",
                ),
                snippet: "HTTP/1.1 302 Found\nCache-Control: no-store\nLocation: https://example.org/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.org/",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(OPTIONS — \u{a7}9.2.3 defines no caching semantics for it, so no freshness would store it)",
                ),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 403 Forbidden\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(POST — \u{a7}9.3.3 makes explicit freshness half of what would store it)"),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 403 Forbidden\n",
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

            // A response to a method that defines no caching semantics is not
            // stored at any freshness it states either, and for the reason one
            // clause earlier: § 3's conjunction opens with the request method,
            // and § 9.2.3 names the three that qualify. An `OPTIONS` or a
            // `TRACE` reaches this rule's report site by advertising no
            // freshness and carrying a status § 15.1 leaves out — and there is
            // no `max-age` its sender could add that would change the answer,
            // so the finding names a repair that does not exist.
            //
            // `POST` is on § 9.2.3's list and stays asked, which is where this
            // parts from `cache_control_present` next door. That rule warns
            // about a heuristic § 9.3.3 never lets a POST response reach; this
            // one says the response is unstorable and asks for freshness, and
            // for a POST explicit freshness is half of exactly what § 9.3.3
            // requires to make it storable. The advice is takeable, so it is
            // given.
            // cite(RFC 9111 § 3): "the request method is understood by the cache"
            if !crate::helpers::stored_response::defines_caching_semantics(&tx.request.method) {
                return None;
            }

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

            // A `304` is the third response this rule was asking for a repair
            // that does not exist, and it is the one with a sentence naming the
            // fields it *does* owe. § 4.3.4 has a cache take a 304 and update
            // the header fields of the stored responses it identifies; no cache
            // keeps the 304 itself, so "no cache may store this response" is
            // true of every 304 ever sent and says nothing to its sender.
            //
            // **And where a `Cache-Control` really is owed, another sentence
            // owes it.** § 15.4.5 requires a 304 to generate `Cache-Control`
            // and `Expires` — but only the ones the `200` to the same request
            // would have carried, which makes the obligation conditional on an
            // exchange this message does not contain. Asking every 304 for
            // freshness contradicts the section that governs the field here;
            // asking the ones that dropped it is `status_304_field_missing`,
            // which reads that condition against the `200` it saw. So this is a
            // hand-off rather than a hole, and measurably: over a sample of
            // real traffic, of the 304s answering a 200 that had been seen for
            // the same request, exactly one had a 200 that stated freshness and
            // then withheld it, and that entry reports it.
            // cite(RFC 9111 § 4.3.4): "For each stored response identified, the cache MUST update its header fields with the header fields provided in the 304 (Not Modified) response, as per Section 3.2."
            // cite(RFC 9110 § 15.4.5): "The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request:"
            if status == 304 {
                return None;
            }

            // `no-store` is the next term of the conjunction, and it fails the
            // same way the two above do: § 3 states it before the one about
            // freshness, so a response carrying it is unstorable whatever
            // lifetime it also advertises. Asking such a sender for `max-age`
            // names a repair that does not exist -- the third time this rule
            // has had that shape, after the method and the interim status.
            //
            // Both messages are read because the directive is defined twice.
            // § 3 gives the response's; § 5.2.1.5 gives the request the same
            // power over the response it provoked, so a reader of one of them
            // answers half the question. The helper reads both, and is the
            // same one every other rule in this corner already asks.
            // cite(RFC 9111 § 3): "the no-store cache directive is not present in the response"
            if crate::helpers::stored_response::no_store_forbids(&tx.request.headers, &resp.headers)
            {
                return None;
            }

            // What is left is § 3's last term, a disjunction, asked through the
            // reader `storage_allowed` asks it through so the two cannot read
            // it differently. Its members are the heuristically cacheable
            // status (§ 15.1's list), `public`, `private`, `Expires`, `max-age`
            // and `s-maxage`.
            //
            // `public` and `private` withdraw the finding rather than soften
            // it. A `public` response is stored on that directive alone, and
            // § 4.2.2 extends the heuristic to it, so the cache calculates the
            // very lifetime this entry says the response lacks; a private
            // cache may keep a `private` one on the same terms, and nothing on
            // the wire says which kind of cache a reader is standing in for.
            //
            // **The freshness members are names, not values that parse.** A
            // malformed `Expires` or `max-age` is read as already expired
            // (§ 5.3, § 4.2.1), which is a stale copy a cache keeps. This arm
            // once counted only a lifetime that parsed, so `Expires: -1` on a
            // 302 drew "lacks explicit freshness information (... or Expires)"
            // beside `expires_malformed`: a second finding about the field,
            // and untrue of the value. The malformation is the field's own
            // entry to report.
            //
            // § 5.2.3's cache extension is the one member still unread, and it
            // needs a registry this rule does not have. That omission leaves a
            // finding standing where the others withdraw one, which is the
            // direction worth naming rather than leaving to be discovered.
            // cite(RFC 9110 § 15.1): "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"
            // cite(RFC 9111 § 3): "a public response directive"
            // cite(RFC 9111 § 3): "a private response directive, if the cache is not shared"
            // cite(RFC 9111 § 3): "an Expires header field"
            // cite(RFC 9111 § 4.2.2): "on responses without explicit freshness that have been marked as explicitly cacheable (e.g., with a public response directive)"
            if crate::helpers::stored_response::licenses_storage(status, &resp.headers) {
                return None;
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

    /// A `304` says nothing this entry can ask for, whatever it carries: no
    /// cache keeps the 304 itself, and the one sentence that asks a 304 for
    /// freshness asks it conditionally on an exchange this message does not
    /// hold. The `412` beside it is the control — the same shape on a status
    /// that is a stored response, still reported.
    #[rstest]
    #[case::bare(304, vec![])]
    #[case::with_a_validator(304, vec![("etag", "\"abc\"")])]
    #[case::with_freshness(304, vec![("cache-control", "max-age=60")])]
    fn a_304_is_not_a_response_a_cache_stores(
        #[case] status: u16,
        #[case] headers: Vec<(&str, &str)>,
    ) {
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &headers);
        assert!(
            crate::test_helpers::run_rule(
                &StatusAndCachingSemantics,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "status_and_caching_semantics",
                ]),
            )
            .is_none(),
            "{status} {headers:?}"
        );
    }

    #[rstest]
    #[case(302, vec![], true)]
    #[case(302, vec![("cache-control", "max-age=60")], false)]
    #[case(302, vec![("cache-control", "s-maxage=10")], false)]
    // A freshness member § 3 names is present whatever its value: an invalid
    // one is read as already expired (§ 4.2.1, § 5.3), a stale copy a cache
    // keeps, and the malformation is the field's own entry to report.
    #[case(302, vec![("cache-control", "max-age=-1")], false)]
    #[case(302, vec![("cache-control", "max-age=abc")], false)]
    #[case(302, vec![("cache-control", "s-maxage=soon")], false)]
    #[case(302, vec![("expires", "-1")], false)]
    #[case(302, vec![("expires", "0")], false)]
    #[case(302, vec![("cache-control", "public"), ("cache-control", "max-age=5")], false)]
    // `public` on its own was never pinned, and it is the row that was wrong:
    // the case above passes on the `max-age` and says nothing about the
    // directive beside it. § 3 stores the response on that directive alone and
    // § 4.2.2 lets the cache calculate the lifetime, so there is nothing to
    // ask the sender for. `private` is the same disjunction's next member.
    #[case(302, vec![("cache-control", "public")], false)]
    #[case(302, vec![("cache-control", "private")], false)]
    #[case(302, vec![("cache-control", "public, no-cache")], false)]
    // `no-store` fails a term of § 3 that comes before the freshness one, so
    // the response is unstorable and no lifetime would change that. Pinned
    // beside a `no-store` that also states a lifetime, because the answer has
    // to be the same for both: the directive decides, not the lifetime.
    #[case(302, vec![("cache-control", "no-store")], false)]
    #[case(302, vec![("cache-control", "no-store, max-age=60")], false)]
    #[case(302, vec![("cache-control", "no-store, no-cache, must-revalidate")], false)]
    // A qualified `no-store` is not the directive § 3 names: the response form
    // takes no argument, so `no-store="x"` is something else and leaves the
    // question asked. This is the helper's own reading, pinned here because
    // this rule is what a user meets it through.
    #[case(302, vec![("cache-control", "no-store=\"x\"")], true)]
    // Neither term reaches a status § 15.1 already covers, so a 200 stays
    // silent for the reason it always did and not for a new one.
    #[case(200, vec![("cache-control", "no-store")], false)]
    #[case(200, vec![("cache-control", "public")], false)]
    // The neighbouring directives that do NOT license storage keep the finding
    // standing, which is the half that proves the change is not a blanket
    // silence: `no-cache` and `must-revalidate` are about reuse, not storage.
    #[case(302, vec![("cache-control", "no-cache")], true)]
    #[case(302, vec![("cache-control", "must-revalidate")], true)]
    #[case(302, vec![("cache-control", "immutable")], true)]
    #[case(503, vec![("expires", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case(503, vec![("expires", "not-a-date")], false)]
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

    /// RFC 9111 \u{a7} 3's conjunction opens with the request method, and a `403`
    /// that states no freshness reaches the report site whatever asked for it.
    /// `OPTIONS` and `TRACE` define no caching semantics (\u{a7} 9.2.3), so no
    /// `max-age` their senders could add would make a cache hold the response
    /// and the finding names a repair that does not exist.
    ///
    /// **`POST` is the row that separates this rule from `cache_control_present`
    /// next door**, and it is pinned in both files for that reason. There the
    /// harm is a heuristic \u{a7} 9.3.3 never lets a POST response reach, so the
    /// question is dropped; here the finding is that nothing may store the
    /// response, and \u{a7} 9.3.3 makes explicit freshness half of what would
    /// change that. The advice is takeable, so it is still given.
    #[rstest]
    #[case("GET", true)]
    #[case("HEAD", true)]
    #[case("POST", true)]
    #[case("OPTIONS", false)]
    #[case("TRACE", false)]
    #[case("PUT", false)]
    #[case("DELETE", false)]
    fn the_method_decides_whether_the_question_is_asked_at_all(
        #[case] method: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = StatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(403, &[]);
        tx.request.method = method.to_string();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "method {method} judged wrongly: {v:?}"
        );
        Ok(())
    }

    /// § 5.2.1.5 gives the request the same power over the response it
    /// provoked that § 3 gives the response over itself, so the term is
    /// answered by either message. A reader of one of them answers half the
    /// question, and the half it misses is the one no response header shows.
    ///
    /// The `false` row is the control: the same request directive on a status
    /// § 15.1 covers changes nothing, because that response was never going to
    /// draw this finding for a reason of its own.
    #[rstest]
    #[case(302, "no-store", false)]
    #[case(302, "no-cache", true)]
    #[case(302, "max-age=0", true)]
    #[case(200, "no-store", false)]
    fn the_request_carries_the_no_store_term_too(
        #[case] status: u16,
        #[case] request_directive: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = StatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(status, &[]);
        tx.request.headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_str(request_directive)?,
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "request Cache-Control {request_directive:?} on {status} judged wrongly: {v:?}"
        );
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
