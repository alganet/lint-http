// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_NO_CACHE_IGNORED, RFC_9111_5_2_2_4};
use crate::violations::ViolationDef;

/// One entry: a response the unqualified directive said to revalidate,
/// reused without a conditional request.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_NO_CACHE_IGNORED];

/// Ensure that responses marked `no-cache` are not reused without performing
/// a conditional revalidation when a validator is available.
///
/// The `no-cache` directive (RFC 9111 §5.2.2.4) permits a cache to store a
/// response but requires the cache to submit a request to the origin server and
/// successfully validate the stored entry before using it to satisfy a
/// subsequent request.  In practical terms this means that if a prior response
/// for the same resource included `Cache-Control: no-cache` and also contained
/// at least one validator (`ETag` or `Last-Modified`), then any later request
/// for that resource **should** include a corresponding conditional header
/// (`If-None-Match` or `If-Modified-Since`).  A bare unconditional request is
/// evidence that the client may have reused the cached entry without
/// revalidation.
///
/// This stateful rule scans the transaction history (which the engine already
/// scopes to the same client+URI) and locates the most recent response that
/// carried a `no-cache` directive *and* that the request now presented could
/// have been served from at all (§4): the same method, or a `HEAD` against a
/// stored `GET`, and only a method with caching semantics leaves a stored
/// response behind in the first place.  A cache satisfies neither an `OPTIONS`
/// nor a `TRACE` from a stored `GET`, and stores no response to either of them
/// to reuse against itself, so on those there is no entry and no reuse to
/// report.  If that response also provided a validator and the current request
/// is unconditional, the rule emits a violation.
///
/// Only the unqualified form is enforced: the qualified `no-cache="field"` form
/// lets a cache reuse the response while revalidating or excluding just the
/// listed fields, so it is not flagged.
///
/// The check is intentionally conservative: it does **not** attempt to
/// distinguish between a cache reuse and a normal fresh fetch, and it does not
/// inspect request-side `Cache-Control: no-cache` clauses.  The presence of a
/// validator is required so that the rule does not warn on responses that
/// could not possibly be revalidated.
pub struct NoCacheRevalidation;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3",
    note: "Validation (the conditional request that satisfies no-cache)",
};
const RFC_9110_9_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.3",
    note: "Methods and Caching (which methods leave a stored response behind at all)",
};
const RFC_9111_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4",
    note:
        "Constructing Responses from Caches (which stored response may answer a presented request)",
};

impl RuleMeta for NoCacheRevalidation {
    fn id(&self) -> &'static str {
        "no_cache_revalidation"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful no-cache revalidation")
    }

    fn description(&self) -> &'static str {
        "The `no-cache` cache-control directive (RFC 9111 §5.2.2.4) permits a cache to store a response, but it **must not** use that stored entry to satisfy a subsequent request without first validating it with the origin server.  In practice, caches are expected to issue a conditional request using a validator (usually an `ETag` or `Last-Modified` value) when they have one; if no validator is available the cache may perform an unconditional request, which still contacts the origin server.\n\nThis stateful rule reconstructs a small portion of cache state for the current client+resource by locating the most recent prior response that included `Cache-Control: no-cache` and that the request now presented was allowed to be answered from (§4): the same method, or a `HEAD` against a stored `GET`.  Only GET, HEAD and POST have caching semantics at all, so a response to an `OPTIONS` or a `TRACE` is no stored entry even against a later request of its own method, and a stored `GET` is no candidate for an `OPTIONS`, a `TRACE`, or an unsafe method — where nothing could have been reused there is no reuse to report.  If that response also carried a validator and the current request is unconditional (no `If-None-Match` or `If-Modified-Since` headers), the rule emits a warning.  The presence of validators is required to avoid false alarms in cases where the entry could not possibly be revalidated.\n\nThe check deliberately ignores request-side `Cache-Control: no-cache` clauses and makes no attempt to calculate freshness; it simply tracks whether a conditional header was omitted.  Only the unqualified directive is enforced: a qualified `no-cache=\"field\"` response may be reused (revalidating only the named fields) and is not flagged.  **What this rule does not observe is the reuse itself.** §5.2.2.4 bars using a stored `no-cache` response *without forwarding it for validation*, and this implementation reads the seam between a client and an origin — a cache that had answered from its stored entry would have put nothing on that seam. Every request reaching this rule is one the cache declined to answer, so the forwarding the directive requires has happened, and §4.3 says a cache *can* use the conditional mechanism rather than that it must. The finding is therefore the narrower one the wire supports: a validator was held and not sent, costing a body where a `304` would have done. That is why it is a `warn` whose obligation is recorded as unstated — the `MUST NOT` is addressed to the cache, not to the client the finding names. **And `no-store` beside it is answered first.** The two directives arrive together on more than half the responses that carry either — `no-cache, no-store, must-revalidate` is the line — and they say different things: `no-cache` forbids reuse without validation, while `no-store` (RFC 9111 §3, and §5.2.1.5 for the request's copy of it) forbids the storing that would have given the client something to validate. Where both are present nothing was stored, so the rule skips that response and looks past it for an entry an earlier exchange did leave. This rule complements `max_age_directive_valid` and `must_revalidate_enforced` by focussing on the specific behaviour mandated by the `no-cache` directive."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2_2_4, RFC_9111_4_3, RFC_9110_9_2_3, RFC_9111_4]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// examines both the request and prior responses for the same
    /// client+resource (history is filtered by the engine accordingly).
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— conditional request satisfies no-cache requirement"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n< ETag: \"v1\"\n\n# later:\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # conditional request used; no violation",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— no validator means unconditional request is acceptable"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n\n# client cannot compose a conditional request; unconditional fetch is fine\n> GET /resource HTTP/1.1\n> Host: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a method the stored entry could not have answered"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n< ETag: \"v1\"\n\n# later, a different method on the same resource:\n> OPTIONS /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 405 Method Not Allowed\n\n# no cache answers an OPTIONS from a stored GET, so nothing was reused",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— reused entry without revalidation"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n< ETag: \"v1\"\n\n# later, client repeats request but omits validator\n> GET /resource HTTP/1.1\n> Host: example.com\n# violation: cached response required conditional revalidation",
            },
        ]
    }
}

impl Rule for NoCacheRevalidation {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The most recent past response that carried no-cache AND that this
            // request could have been served from. An entry that was never a
            // candidate was never reused: no cache answers an OPTIONS or a
            // TRACE from a stored GET, and neither leaves a stored response
            // behind to reuse against itself, so on those the origin answered
            // -- as the 405s such requests come back with attest.
            //
            // The method belongs in the search rather than after it, for the
            // reason its sibling found: asked only for the newest no-cache
            // response, this stops at a stored HEAD and calls it the entry a
            // GET reused, while the stored GET actually behind it goes
            // unreported.
            // cite(RFC 9111 § 4): "the request method associated with the stored response allows it to be used for the presented request"
            //
            // And an entry § 3 forbade storing is not one either. `no-cache`
            // and `no-store` arrive together on more than half the responses
            // that carry either — `no-cache, no-store, must-revalidate` is the
            // line — and the two say different things: the first forbids reuse
            // without validation, the second forbids the storing that would
            // give the client something to validate. Where both are present
            // this rule was reporting a client for not revalidating a response
            // it was never allowed to keep.
            // cite(RFC 9111 § 3): "A cache MUST NOT store a response to a request unless:"
            let (_, prev_resp) = history.responses().find(|(prev_tx, resp)| {
                header_has_no_cache(&resp.headers)
                    && crate::helpers::stored_response::storage_allowed(
                        &prev_tx.request.headers,
                        &resp.headers,
                    )
                    && crate::helpers::stored_response::method_allows(
                        &prev_tx.request.method,
                        &tx.request.method,
                    )
            })?;

            // only warn if the original response supplied a validator; without one
            // there is no way to perform a conditional revalidation, so an
            // unconditional request may still be legitimate.
            let has_validator = prev_resp.headers.contains_key("etag")
                || prev_resp.headers.contains_key("last-modified");
            if !has_validator {
                return None;
            }

            // A conditional request (carrying a precondition header field) is the validation §5.2.2.4
            // requires; an unconditional one is evidence the entry may have been reused as-is.
            // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields."
            let has_conditional = tx.request.headers.contains_key("if-none-match")
                || tx.request.headers.contains_key("if-modified-since");

            // cite(RFC 9111 § 5.2.2.4): "The no-cache response directive, in its unqualified form (without an argument), indicates that the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
            if !has_conditional {
                return Some(ctx.report_with(&CACHE_CONTROL_NO_CACHE_IGNORED, "An earlier response marked 'no-cache' carried a validator, and this request for it went out with no If-None-Match or If-Modified-Since. The response may not be reused without forwarding for validation, and this request is that forwarding; sending the validator with it would have let the origin answer 304 instead of resending the body".into()));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Look for an unqualified `no-cache` directive in any Cache-Control field line.
///
/// Only the bare form forbids reuse without revalidation; the qualified form
/// lets a cache reuse the response, revalidating or excluding only the listed
/// fields, so it is not what this rule enforces.
// cite(RFC 9111 § 5.2.2.4): "The qualified form of the no-cache response directive, with an argument that lists one or more field names, indicates that a cache MAY use the response to satisfy a subsequent request"
fn header_has_no_cache(headers: &hyper::HeaderMap) -> bool {
    crate::helpers::cache_control::has_unqualified(headers, "no-cache")
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &NoCacheRevalidation;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev(headers: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, headers);
        tx.request.method = "GET".to_string();
        tx
    }

    #[test]
    fn no_history_no_violation() {
        let rule = NoCacheRevalidation;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        assert!(v.is_none());
    }

    /// A stored `GET` marked `no-cache` answers a later `GET`, and a `HEAD` off
    /// the back of it, and nothing else. The methods below are the ones a cache
    /// never serves from that entry, so on them no entry was reused and the
    /// origin answered — which the 405s such requests come back with confirm.
    #[rstest::rstest]
    #[case("GET", true)]
    #[case("HEAD", true)]
    #[case("OPTIONS", false)]
    #[case("TRACE", false)]
    #[case("PUT", false)]
    #[case("DELETE", false)]
    #[case("POST", false)]
    fn only_a_method_the_stored_entry_could_answer_is_reuse(
        #[case] presented: &str,
        #[case] reports: bool,
    ) {
        let rule = NoCacheRevalidation;
        let prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"v\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = presented.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        assert_eq!(v.is_some(), reports, "presented method {presented}");
    }

    /// The same method on both sides is still not reuse when that method stores
    /// nothing: an `OPTIONS` answered after an earlier `OPTIONS` had no entry
    /// behind it to be reused.
    #[rstest::rstest]
    #[case("OPTIONS")]
    #[case("TRACE")]
    fn a_method_that_stores_nothing_is_no_entry_even_against_itself(#[case] method: &str) {
        let rule = NoCacheRevalidation;
        let mut prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"v\"")]);
        prev.request.method = method.to_string();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        assert!(v.is_none(), "stored and presented {method}");
    }

    /// A `no-cache` `GET` entry with a `no-cache` `HEAD` response in front of
    /// it. The `HEAD` is the newer match but is no candidate for a presented
    /// `GET`, and the entry that `GET` would have been served from is the one
    /// behind it — so the search has to look past the first match, not stop at
    /// it.
    #[test]
    fn a_newer_entry_this_request_could_not_use_does_not_hide_one_it_could() {
        let rule = NoCacheRevalidation;
        let marked: &[(&str, &str)] = &[("cache-control", "no-cache"), ("etag", "\"v\"")];
        let older_get = make_prev(marked);
        let mut newer_head = make_prev(marked);
        newer_head.request.method = "HEAD".to_string();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        // newest first
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            newer_head, older_get,
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn no_cache_parsing_variants() {
        // basic case-insensitive match
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("max-age=0, no-cache"),
        );
        assert!(header_has_no_cache(&headers));
        // different casing and extra whitespace
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("  NO-CACHE  "),
        );
        assert!(header_has_no_cache(&headers));
        // semicolon as a separator, unqualified no-cache
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("private; no-cache"),
        );
        assert!(header_has_no_cache(&headers));
        // qualified `no-cache="field"` is NOT the reuse-forbidding unqualified form
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("private, no-cache=\"field\""),
        );
        assert!(!header_has_no_cache(&headers));
        // negative control: header present but no no-cache directive
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("max-age=60, public"),
        );
        assert!(!header_has_no_cache(&headers));
    }

    #[test]
    fn qualified_no_cache_with_validator_not_flagged() {
        // A qualified `no-cache="field"` response MAY be reused (revalidating only the named
        // fields), so an unconditional follow-up must not be flagged (RFC 9111 §5.2.2.4).
        let rule = NoCacheRevalidation;
        let mut prev = make_prev(&[
            ("cache-control", "no-cache=\"Set-Cookie\""),
            ("etag", "\"a\""),
        ]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        assert!(v.is_none(), "qualified no-cache must not be flagged");
    }

    #[test]
    fn no_cache_unconditional_flagged() {
        let rule = NoCacheRevalidation;
        // `no-cache` responses without a validator should not trigger a
        // violation (see `no_validator_no_violation`), so include a validator
        // here to exercise the warning path.
        let mut prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        );
        // The entry an operator configures, and the level that says how far
        // the evidence reaches: an unconditional request crossing this seam is
        // the forwarding § 5.2.2.4 asks for, not the reuse it forbids, and
        // § 4.3 lets a cache use the conditional mechanism without requiring
        // it. So the finding is the unsent validator, at `warn`.
        let v = v.expect("a finding");
        assert_eq!(v.violation, "cache_control_no_cache_ignored");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("no-cache"));
        // The claim the message may no longer make, pinned as a value that
        // stays true of the entry: nothing observed here was reused.
        assert!(!v.message.contains("reuse of"), "{}", v.message);
        assert!(v.message.contains("If-None-Match"), "{}", v.message);
    }

    #[test]
    fn conditional_after_no_cache_allowed() {
        let rule = NoCacheRevalidation;
        let mut prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        )
        .is_none());
    }

    /// `no-cache` and `no-store` arrive together on more than half the
    /// responses that carry either, and they say different things: the first
    /// forbids reuse without validation, the second forbids the storing that
    /// would give the client something to validate with. Where both are
    /// present the client held nothing, so it declined nothing.
    #[rstest::rstest]
    #[case(&[("cache-control", "no-cache, no-store"), ("etag", "\"a\"")], &[])]
    #[case(&[("cache-control", "no-store, no-cache, must-revalidate"), ("etag", "\"a\"")], &[])]
    #[case(
        &[("cache-control", "no-cache"), ("etag", "\"a\"")],
        &[("cache-control", "no-store")]
    )]
    fn a_response_no_cache_stored_is_no_entry_to_revalidate(
        #[case] prev_response: &[(&str, &str)],
        #[case] prev_request: &[(&str, &str)],
    ) {
        let rule = NoCacheRevalidation;
        let mut prev = make_prev(prev_response);
        prev.request.uri = "/resource".to_string();
        prev.request.headers = crate::test_helpers::make_headers_from_pairs(prev_request);
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "no_cache_revalidation"
                ]),
            )
            .is_none(),
            "no cache held this response, so no validator was withheld"
        );
    }

    /// A response no cache was allowed to keep does not unstore the entry an
    /// earlier exchange left, so the search looks past it rather than stopping.
    #[test]
    fn a_no_store_response_does_not_hide_the_entry_behind_it() {
        let rule = NoCacheRevalidation;
        let base = chrono::Utc::now();
        let mut older = make_prev(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        older.request.uri = "/resource".to_string();
        older.client = crate::test_helpers::make_test_client();
        older.timestamp = base;
        let mut newer = make_prev(&[("cache-control", "no-cache, no-store"), ("etag", "\"b\"")]);
        newer.request.uri = "/resource".to_string();
        newer.client = crate::test_helpers::make_test_client();
        newer.timestamp = base + chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(2);

        // newest first
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![newer, older]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        )
        .is_some());
    }

    #[test]
    fn no_validator_no_violation() {
        let rule = NoCacheRevalidation;
        let mut prev = make_prev(&[("cache-control", "no-cache")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_cache_revalidation"]),
        )
        .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "no_cache_revalidation");
        // Enabling the rule with a valid config must pass validation.
        crate::rules::validate_rules(&cfg).unwrap();
        // Ensure the rule is registered in the global RULES registry.
        assert!(crate::rules::RULES
            .iter()
            .any(|rule| rule.id() == "no_cache_revalidation"));
    }
}
