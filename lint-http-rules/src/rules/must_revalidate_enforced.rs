// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_MUST_REVALIDATE_IGNORED, RFC_9111_5_2_2_2};
use crate::violations::ViolationDef;

/// One entry: a stale response the directive said to validate first,
/// reused without a validator.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_MUST_REVALIDATE_IGNORED];

/// Ensure that responses containing the `must-revalidate` cache directive are
/// never reused once they are stale without first performing revalidation.
///
/// The `must-revalidate` directive (RFC 9111 §5.2.2.2) instructs caches that
/// once a stored response becomes stale it **must not** be served to satisfy a
/// request unless the entry has been successfully revalidated with the origin
/// server.  In practice this means that, for any prior response bearing
/// `Cache-Control: must-revalidate`, a subsequent request for the same
/// resource should include a conditional header (`If-None-Match` or
/// `If-Modified-Since`) if the response would be stale at the time the request
/// is made.  If the cached entry carried no validator then the cache has no way
/// to revalidate; our lint rules therefore do not flag that situation.
///
/// This rule examines the history for the given client+resource and locates the
/// most recent response that contained a `must-revalidate` directive.  The
/// request now presented must be one that stored response could have answered
/// at all (§4): the same method, or a `HEAD` against a stored `GET`, and only a
/// method with caching semantics leaves a stored response behind in the first
/// place.  A cache satisfies neither an `OPTIONS` nor a `TRACE` from a stored
/// `GET`, and stores no response to either of them to reuse against itself, so
/// on those there is no entry and no reuse to report.  It then
/// computes an estimated "age" for that response (using the `Age` header and
/// elapsed time) and compares it against whatever explicit freshness lifetime
/// the response advertised.  The lifetime is derived first from a
/// `max-age=<seconds>` directive (if present) and otherwise from an `Expires`
/// header.  Responses that provide neither value are considered immediately
/// stale, as per the specification's guidance for entries lacking explicit
/// freshness information.  If the calculated age exceeds the freshness lifetime
/// *and* the current request is unconditional, a violation is emitted.  If a
/// validator (ETag or Last-Modified) was never seen on the original response,
/// the rule does not warn, because there is nothing the client could have done
/// to revalidate.
pub struct MustRevalidateEnforced;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
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
const RFC_9111_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
    note: "Freshness (a response is stale once its age reaches its freshness lifetime)",
};
const RFC_9111_4_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3",
    note: "Calculating Age (the response age this rule estimates)",
};
const RFC_9111_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3",
    note: "Validation (revalidating a stale entry before reuse)",
};

impl RuleMeta for MustRevalidateEnforced {
    fn id(&self) -> &'static str {
        "must_revalidate_enforced"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful must-revalidate enforcement")
    }

    fn description(&self) -> &'static str {
        "The `must-revalidate` cache-control directive (RFC 9111 §5.2.2.2) tells caches that once a stored response becomes stale it **must not** be used to satisfy subsequent requests unless the entry has been successfully revalidated with the origin server.  Serving a stale value without revalidation can expose clients to outdated or incorrect data.\n\nThis rule reconstructs a small piece of cache state for a given client+resource by locating the most recent prior response that included `Cache-Control: must-revalidate`.  The request now presented must be one that stored response was allowed to answer in the first place (§4): the same method, or a `HEAD` against a stored `GET`.  Only GET, HEAD and POST have caching semantics at all, so a response to an `OPTIONS` or a `TRACE` is no stored entry even against a later request of its own method.  A stored `GET` is likewise no candidate for an `OPTIONS`, a `TRACE`, or an unsafe method, and where nothing could have been reused there is no reuse to report.  It estimates the age of that entry using the `Age` header (if any) plus the time elapsed since the response was observed. The advertised freshness lifetime is taken from a `max-age` directive, if present, or else from an `Expires` header; replies that provide neither are considered immediately stale.  If the computed age exceeds or **equals** the freshness lifetime (a zero lifetime is therefore immediately stale) *and* the current request is unconditional (no `If-None-Match` or `If-Modified-Since`) and the original response carried a validator, the rule raises a warning.  Directive names in `Cache-Control` are parsed case-insensitively, so `Max-Age` or `MAX-AGE` are treated the same as the canonical lowercase form.  Clients that lack validators are not flagged because they have no way to revalidate.\n\n**The reuse the directive forbids is not what this reads.** §5.2.2.2 binds a cache, and this implementation watches the wire between a client and an origin: had the client's cache reused the stale entry, no request would have crossed it. Every finding here therefore sits on a request the cache did *not* satisfy — the directive honoured — and what it reports is the narrower fact the wire carries, that a validator the client held went unsent and a full body came back where a `304` would have served. The level follows: a `warn` whose obligation is unstated, because the `MUST NOT` binds the cache and not the client the finding names. This stateful check complements the existing `max_age_directive_valid` rule by covering situations where `must-revalidate` is present but no explicit `max-age` is provided (stale data is prohibited immediately), and by emphasising the intent of the `must-revalidate` directive when both rules are enabled."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_2_2_2,
            RFC_9110_9_2_3,
            RFC_9111_4,
            RFC_9111_4_2,
            RFC_9111_4_2_3,
            RFC_9111_4_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// we need to inspect both the request and prior responses
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— fresh entry reused without conditional headers"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60, must-revalidate\n\n# thirty seconds later the cache is still fresh and may satisfy a request\n# without conditional headers.  The linter does not observe a violation.",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— stale entry revalidated"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1, must-revalidate\n< ETag: \"v1\"\n\n# later, after expiry:\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # conditional request used",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— must-revalidate with no freshness never reused"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: must-revalidate\n< ETag: \"v2\"\n\n# client must revalidate on every request; a conditional request is fine\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v2\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a method the stored entry could not have answered"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1, must-revalidate\n< ETag: \"v1\"\n\n# later, after expiry, a different method on the same resource:\n> OPTIONS /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 405 Method Not Allowed\n\n# no cache answers an OPTIONS from a stored GET, so nothing was reused",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— stale entry reused without conditional request"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1, must-revalidate\n< ETag: \"v1\"\n\n# several seconds later the client fetches again but omits validators\n> GET /resource HTTP/1.1\n> Host: example.com\n# violation: stale according to must-revalidate semantics",
            },
        ]
    }
}

impl Rule for MustRevalidateEnforced {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The most recent past response that carried must-revalidate AND that
            // this request could have been served from. Staleness only matters for
            // an entry that was a candidate at all: no cache answers an OPTIONS or
            // a TRACE from a stored GET, so on those nothing was reused and the
            // origin answered -- as the 405s such requests come back with attest.
            //
            // The method belongs in the search, not after it. Asked only for the
            // newest must-revalidate response, this took a stored HEAD as the entry
            // a GET had reused, and a GET that really had a stale GET entry behind
            // it went unreported because a HEAD sat in front of it.
            // cite(RFC 9111 § 4): "the request method associated with the stored response allows it to be used for the presented request"
            let (prev_tx, prev_resp) = history.responses().find(|(prev_tx, resp)| {
                header_has_must_revalidate(&resp.headers)
                    && crate::helpers::stored_response::method_allows(
                        &prev_tx.request.method,
                        &tx.request.method,
                    )
            })?;

            // Freshness lifetime advertised by the response. The helper owns the §4.2.1
            // derivation (max-age wins, else Expires − Date), returning zero when no explicit
            // lifetime is available.
            let freshness_lifetime = crate::helpers::cache_control::compute_freshness_lifetime(
                &prev_resp.headers,
                prev_tx.timestamp,
            );

            // Age stated by the response plus the time it has since spent in our
            // record; the helper owns that estimate and what it leaves out.
            let current_age = crate::helpers::cache_control::estimated_age(
                &prev_resp.headers,
                prev_tx.timestamp,
                tx.timestamp,
            );

            // A conditional request (carrying a precondition header field) is how a client
            // revalidates — the "successfully validated by the origin" that §5.2.2.2 requires.
            // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields."
            let has_conditional = tx.request.headers.contains_key("if-none-match")
                || tx.request.headers.contains_key("if-modified-since");

            // A response is stale once its age reaches its freshness lifetime. §4.2's normative
            // calculation is `response_is_fresh = (freshness_lifetime > current_age)` (a sourcecode
            // block, not machine-citeable), so stale is `>=` — which also makes a zero lifetime
            // (max-age=0 or no explicit freshness) immediately stale.
            // cite(RFC 9111 § 4.2): "A "fresh" response is one whose age has not yet exceeded its freshness lifetime. Conversely, a "stale" response is one where it has."
            if current_age >= freshness_lifetime && !has_conditional {
                // warn only if there was a validator on the original response
                let has_validator = prev_resp.headers.contains_key("etag")
                    || prev_resp.headers.contains_key("last-modified");
                // cite(RFC 9111 § 5.2.2.2): "The must-revalidate response directive indicates that once the response has become stale, a cache MUST NOT reuse that response to satisfy another request until it has been successfully validated by the origin, as defined by Section 4.3."
                if has_validator {
                    return Some(ctx.report_with(&CACHE_CONTROL_MUST_REVALIDATE_IGNORED, format!(
                            "Stored response carrying 'must-revalidate' is stale (age {} >= freshness {}) and held a validator, but this request for it went out with no If-None-Match or If-Modified-Since. Forwarding the request is what the directive asks for; a conditional one would have let the origin answer 304 instead of resending the body",
                            current_age, freshness_lifetime
                        )));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Helper to detect presence of a must-revalidate directive in Cache-Control
/// headers. The directive takes no argument, so the bare form is the only form.
fn header_has_must_revalidate(headers: &hyper::HeaderMap) -> bool {
    crate::helpers::cache_control::has_unqualified(headers, "must-revalidate")
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MustRevalidateEnforced;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev(
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.method = "GET".to_string();
        tx
    }

    #[test]
    fn no_history_no_violation() {
        let rule = MustRevalidateEnforced;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unrelated_history_ignored() {
        let rule = MustRevalidateEnforced;
        let prev = make_prev(200, &[("cache-control", "max-age=60")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn header_has_must_revalidate_variations() {
        let mut hm = hyper::HeaderMap::new();
        // no header -> false
        assert!(!header_has_must_revalidate(&hm));
        hm.insert("cache-control", "must-revalidate".parse().unwrap());
        assert!(header_has_must_revalidate(&hm));
        // case insensitivity
        hm.clear();
        hm.insert("cache-control", "MuSt-ReVaLiDaTe".parse().unwrap());
        assert!(header_has_must_revalidate(&hm));
        // comma separation
        hm.clear();
        hm.insert(
            "cache-control",
            "public, must-revalidate, max-age=0".parse().unwrap(),
        );
        assert!(header_has_must_revalidate(&hm));
        // semicolon separation
        hm.clear();
        hm.insert(
            "cache-control",
            "max-age=0;must-revalidate".parse().unwrap(),
        );
        assert!(header_has_must_revalidate(&hm));
        // absence
        hm.clear();
        hm.insert("cache-control", "max-age=60".parse().unwrap());
        assert!(!header_has_must_revalidate(&hm));
    }

    #[test]
    fn age_header_and_elapsed_handling() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "must-revalidate, max-age=0"),
                ("age", "5"),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        // set timestamp earlier to test clamp
        tx.timestamp = base - chrono::Duration::seconds(10);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        // current_age should equal age header (5) not negative elapsed
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        // freshness zero and no validator -> no violation
        assert!(v.is_none());
    }

    #[test]
    fn age_header_contributes_to_violation() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        // prev has validator and age 10, max-age 5, so stale
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "must-revalidate, max-age=5"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        // inject age header into response
        prev.response
            .as_mut()
            .unwrap()
            .headers
            .insert("age", hyper::header::HeaderValue::from_static("10"));
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(1);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        // The entry an operator configures, and the level that says how far
        // the evidence reaches: a request arriving on this seam is one the
        // client's cache did *not* answer, so the reuse § 5.2.2.2 forbids is
        // the one event that cannot be witnessed here. What is left is the
        // unsent validator, which is a `warn` and not a broken `MUST`.
        let v = v.expect("a finding");
        assert_eq!(v.violation, "cache_control_must_revalidate_ignored");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        // The claim the message may no longer make, pinned as a value that
        // stays true of the entry: nothing observed here was reused.
        assert!(!v.message.contains("reused"), "{}", v.message);
        assert!(v.message.contains("If-None-Match"), "{}", v.message);
    }

    #[test]
    fn invalid_age_header_treated_as_age_zero() {
        // with the >= comparison an unparseable Age header (treated as zero)
        // combined with a zero freshness lifetime should now be considered
        // stale when a validator is present.
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "must-revalidate, max-age=0"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        // invalid age in response
        prev.response
            .as_mut()
            .unwrap()
            .headers
            .insert("age", hyper::header::HeaderValue::from_static("bad"));
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(1);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some(), "equal age should now be treated as stale");
    }

    #[test]
    fn must_revalidate_with_validator_no_conditional_reports() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[("cache-control", "must-revalidate"), ("etag", "\"v\"")],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn must_revalidate_without_validator_no_violation() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        // previous response has must-revalidate but no validator at all
        let mut prev = make_prev(200, &[("cache-control", "must-revalidate")]);
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn fresh_entity_with_max_age_ok() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=60, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn stale_entity_with_max_age_warns() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=1, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some());
    }

    /// The stored entry is a stale `GET` response carrying `must-revalidate` and
    /// a validator — everything the rule needs except a request the entry could
    /// have answered. Only the method varies, and it decides the verdict on its
    /// own: a cache may answer a `HEAD` from a stored `GET`, and may answer
    /// nothing else, so an `OPTIONS` or a `TRACE` reused no entry to report.
    #[rstest::rstest]
    #[case("GET", true)]
    #[case("HEAD", true)]
    #[case("OPTIONS", false)]
    #[case("TRACE", false)]
    #[case("POST", false)]
    #[case("PUT", false)]
    #[case("DELETE", false)]
    fn only_a_method_the_entry_could_answer_is_reuse(
        #[case] presented: &str,
        #[case] reports: bool,
    ) {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=1, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.method = presented.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert_eq!(v.is_some(), reports, "presented method {presented}");
    }

    /// The same method on both sides is still not reuse when that method stores
    /// nothing: an `OPTIONS` answered after an earlier `OPTIONS` had no entry
    /// behind it to go stale.
    #[rstest::rstest]
    #[case("OPTIONS")]
    #[case("TRACE")]
    fn a_method_that_stores_nothing_is_no_entry_even_against_itself(#[case] method: &str) {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=1, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.request.method = method.to_string();
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none(), "stored and presented {method}");
    }

    /// A stale `GET` entry with a `HEAD` response in front of it. The `HEAD` is
    /// the newer must-revalidate response but is no candidate for a presented
    /// `GET`, and the entry the `GET` would have been served from is the one
    /// behind it — so the search has to look past the first match, not stop at it.
    #[test]
    fn a_newer_entry_this_request_could_not_use_does_not_hide_one_it_could() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let stale = &[
            ("cache-control", "max-age=1, must-revalidate"),
            ("etag", "\"v\""),
        ];
        let mut older_get = make_prev(200, stale);
        older_get.timestamp = base;
        let mut newer_head = make_prev(200, stale);
        newer_head.request.method = "HEAD".to_string();
        newer_head.timestamp = base + chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn stale_entity_revalidated_is_ok() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=1, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn stale_entity_age_equal_warns() {
        // equality should count as stale under the new >= logic
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=5, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some(), "equal age should be considered stale");
    }

    #[test]
    fn zero_max_age_with_validator_immediately_stale() {
        let rule = MustRevalidateEnforced;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=0, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base; // no elapsed time
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_some(), "max-age=0 should be stale immediately");
    }

    #[test]
    fn conditional_before_stale_ok() {
        let rule = MustRevalidateEnforced;
        let ts = chrono::Utc::now();
        let prev = make_prev(
            200,
            &[
                ("cache-control", "max-age=60, must-revalidate"),
                ("etag", "\"v\""),
            ],
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = ts + chrono::Duration::seconds(10);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "must_revalidate_enforced",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "must_revalidate_enforced");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
