// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::CONDITIONAL_REDUNDANT;
use crate::violations::ViolationDef;

/// One entry, and it used to be two findings. The other half — a stale entry
/// refetched without a conditional request — is `cached_validators_reused`'s,
/// whose gate is the wider one, so it went rather than being declared beside
/// it.
static DECLARED: &[&ViolationDef] = &[&CONDITIONAL_REDUNDANT];

/// Ensure that the freshness lifetime advertised by
/// `Cache-Control: max-age=<seconds>` is actually respected by a client or
/// cache when re-requesting a resource.
///
/// The rule looks back at the most recent previous response for the same
/// client+resource that carried a valid `max-age` directive.  It computes an
/// approximate current "age" for that response based on the captured
/// timestamp, any `Age` header, and the elapsed time since the response was
/// seen, and reports one thing: a conditional request
/// (`If-None-Match`/`If-Modified-Since`) issued while the stored response is
/// still within its freshness lifetime, which revalidates a copy nothing had
/// made doubtful.
///
/// The other side of that comparison — a stale entry refetched with no
/// conditional request — was reported here too, and is
/// `cached_validators_reused`'s: that rule asks for a validator on the stored
/// response and no precondition on this request and never consults freshness,
/// so its gate is the wider one and every finding this arm could make it makes
/// already.
pub struct MaxAgeDirectiveValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
    note: "Freshness — fresh/stale definitions, and reuse without contacting the origin as an efficiency opportunity (age itself is calculated per §4.2.3)",
};

impl RuleMeta for MaxAgeDirectiveValid {
    fn id(&self) -> &'static str {
        "max_age_directive_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful max-age directive validity")
    }

    fn description(&self) -> &'static str {
        "Responses tagged with a `Cache-Control` `max-age=<seconds>` directive promise that the representation may safely be reused without revalidation for `<seconds>` seconds after it was stored.\n\nThis rule reconstructs a very small piece of cache state for a given client+resource by examining the most recent prior response that included a parseable `max-age` directive.  It then computes an approximate \"age\" for that stored response using any `Age` header it carried plus the time elapsed since it was observed.\n\nOne thing is reported: sending a **conditional request** (`If-None-Match` or `If-Modified-Since`) while the cached copy is still fresh (age < max‑age).  Revalidation at this point is a redundant round‑trip — a fresh response can be reused without contacting the origin at all.\n\n**Unless the request refused the stored response itself.** A request carrying `no-cache` (or `Pragma: no-cache` with no `Cache-Control`), a `max-age` the entry has outlived, or a `min-fresh` it cannot meet has told the cache not to reuse the entry unvalidated (RFC 9111 §5.2.1). That is what a browser sends on a reload, and it is not reported: the round-trip is the one the client asked for.\n\nIt is an efficiency finding rather than a protocol violation: RFC 9111 §4.2 frames fresh reuse as something a cache *can* do, not an obligation, so the entry names no sentence.  The exception is `Cache-Control: immutable`, which does turn early revalidation into a SHOULD NOT; that is [a separate rule](immutable_cache_never_stale.md).\n\n**The other side of the comparison is not reported here.** A stale entry refetched without a conditional request is [`cached_validators_reused`](cached_validators_reused.md)'s finding, from the same evidence: that rule asks for a validator on the stored response and no precondition on this request, without consulting freshness at all, so it makes every report this rule could make and does not need the freshness estimate to make it.\n\n**Nor is a revalidation after the client's own write.** A `2xx` or `3xx` answer to an unsafe method — `POST`, `PUT`, `PATCH`, `DELETE`, or any method whose safety is unknown — sent by the same client to the same URI makes its cache invalidate the stored responses for that URI (RFC 9111 §4.4): remove them, or mark them as needing validation before they are used. Either way the fresh entry is not one the next request could be served from, and the conditional request is owed. An entry stored after the write is fresh again and is read as before."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_4_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// examines both request and past responses
    /// The client. The directive this rule is named after is the server's,
    /// and that is the yardstick: what the finding reports is a precondition
    /// the *request* carried while the copy it revalidates was still fresh,
    /// and the request is the message the evidence was found in. Its two
    /// siblings — the stale entry refetched without a validator, and the
    /// `immutable` response revalidated early — say the same.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— fresh entry reused without conditional headers"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n\n# thirty seconds later, no request is even sent (cache hit), so linter\n# never observes a transaction.  If a request were visible, it would not\n# include conditional headers during the freshness window.",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— stale entry revalidated"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1\n< ETag: \"v1\"\n\n# later, after expiry:\n> GET /data HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # conditional request used",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a method the stored entry could not have answered"),
                snippet: "> OPTIONS /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=600\n\n# later, a GET for the same resource, carrying a validator from an entry\n# this linter never saw:\n> GET /data HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"\n\n# no cache stores an OPTIONS response, so its max-age describes no entry and\n# this GET revalidated nothing early",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a validator for a variant this request did not select"),
                snippet: "> GET /style.css HTTP/1.1\n> Host: example.com\n> Accept-Encoding: gzip\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=600\n< Vary: Accept-Encoding\n< ETag: \"v1\"\n\n# later, the same resource asked for without a coding preference:\n> GET /style.css HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"\n\n# the fresh entry is the gzip variant, which could not have answered this\n# request, so the round trip was not spent confirming a copy it could use",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a reload, which refuses the stored response itself"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n< Age: 5\n< ETag: \"v1\"\n\n# the user reloads: the browser asks for a response no older than 0s\n> GET /data HTTP/1.1\n> Host: example.com\n> Cache-Control: max-age=0\n> If-None-Match: \"v1\"\n\n# the stored response is older than the request accepts, so validating it is\n# what the client asked for",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a revalidation after the client's own write"),
                snippet: "> GET /items/7 HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n< ETag: \"v1\"\n\n> PUT /items/7 HTTP/1.1\n> Host: example.com\n> Content-Length: 12\n\n< HTTP/1.1 204 No Content\n\n# ten seconds later, the client asks for the item again:\n> GET /items/7 HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"\n\n# the PUT made the cache invalidate its entry for /items/7, so validating\n# it before use is required, not early",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— unnecessary revalidation while still fresh"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n< ETag: \"v1\"\n\n# ten seconds later, client inexplicably revalidates\n> GET /data HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # age 10 < 60, should not revalidate yet",
            },
        ]
    }
}

impl Rule for MaxAgeDirectiveValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The most recent past response carrying a usable max-age **that this
            // request could have been served from**. A response is not an entry
            // because it stated a lifetime; § 3 decides whether one was stored and
            // § 4 decides whether this request could have been answered from it,
            // and both come before the arithmetic below.
            //
            // The conditions belong in the search rather than after it. Asked only
            // for the newest response with a max-age, this took a stored OPTIONS as
            // the entry a GET revalidated early, and a GET that really did hold a
            // fresh GET entry went unreported because an OPTIONS sat in front of it.
            // cite(RFC 9111 § 4): "the request method associated with the stored response allows it to be used for the presented request"
            // cite(RFC 9111 § 4): "request header fields nominated by the stored response (if any) match those presented (see Section 4.1)"
            // cite(RFC 9111 § 3): "A cache MUST NOT store a response to a request unless:"
            //
            // And it reads only what the client's last write left. A 2xx or 3xx
            // to an unsafe method made the cache invalidate every entry before
            // it, and a revalidation of one of those is owed, not early.
            let mut entries =
                crate::helpers::stored_response::responses_since_invalidation(history);
            // The helper owns the directive parse. Two of its behaviours matter
            // here: it returns None when no-cache or no-store is also present —
            // which is what this rule wants, since under those directives
            // revalidating is required rather than wasteful — and it reads the
            // value with an integer parse, so a max-age too large for i64 yields
            // None and the resource is skipped rather than treated as long-lived.
            let (prev_tx, max_age) = entries.find_map(|(prev_tx, resp)| {
                let max_age =
                    crate::helpers::cache_control::get_cache_control_max_age(&resp.headers)?;
                (crate::helpers::stored_response::storage_allowed(
                    &prev_tx.request.headers,
                    resp.status,
                    &resp.headers,
                ) && crate::helpers::stored_response::method_allows(
                    &prev_tx.request.method,
                    &tx.request.method,
                ) && crate::helpers::stored_response::selecting_fields_match(
                    &prev_tx.request.headers,
                    &resp.headers,
                    &tx.request.headers,
                ))
                .then_some((prev_tx, max_age))
            })?;

            // Seed the age from the stored response's Age field. The i64 parse is more
            // permissive than `delta-seconds` (it accepts a leading "+", which `1*DIGIT`
            // does not); §5.1 would have a cache ignore an invalid Age outright, so this
            // consumes a shape the syntax rule flags. Harmless here — the value only
            // shifts an estimate — but the two are deliberately not the same test.
            // cite(RFC 9111 § 5.1): "The "Age" response header field conveys the sender's estimate of the time since the response was generated or successfully validated at the origin server"
            let mut age_val: i64 = 0;
            if let Some(resp) = &prev_tx.response {
                if let Some(hv) = resp.headers.get("age") {
                    if let Ok(s) = hv.to_str() {
                        if let Ok(n) = s.trim().parse::<i64>() {
                            if n >= 0 {
                                age_val = n;
                            }
                        }
                    }
                }
            }

            let elapsed = tx
                .timestamp
                .signed_duration_since(prev_tx.timestamp)
                .num_seconds();
            let elapsed = if elapsed < 0 { 0 } else { elapsed };
            // current_age ≈ Age + time observed here. A deliberate simplification of
            // §4.2.3's algorithm, which also folds in response_delay and resident_time
            // from request/response timing this rule does not record; the clamp to ≥ 0
            // absorbs clock skew. Adequate for a best-effort freshness estimate.
            let current_age = age_val.saturating_add(elapsed);

            let has_conditional = tx.request.headers.contains_key("if-none-match")
                || tx.request.headers.contains_key("if-modified-since");

            // The comparison is the max-age definition applied: an age past the advertised
            // seconds is exactly what makes the stored response stale.
            // cite(RFC 9111 § 5.2.2.1): "The max-age response directive indicates that the response is to be considered stale after its age is greater than the specified number of seconds."
            // cite(RFC 9111 § 4.2): "A "fresh" response is one whose age has not yet exceeded its freshness lifetime"
            // Efficiency heuristic, not a violation: no sentence forbids revalidating
            // early. §4.2 frames reuse-while-fresh as an opportunity ("can"), so a
            // conditional request inside the freshness window is a wasted round-trip
            // — which is what this reports. (`immutable` is the one directive that
            // turns this into a SHOULD NOT, and that is a separate rule.)
            // cite(RFC 9111 § 4.2): "When a response is fresh, it can be used to satisfy subsequent requests without contacting the origin server, thereby improving efficiency"
            //
            // **Early against what the client asked for, not against the entry
            // alone.** A request stating `no-cache`, a `max-age` the entry has
            // outlived (a browser's reload is `max-age=0`) or a `min-fresh` it
            // cannot meet has refused the stored response itself, so the
            // round-trip this reports as wasted is the one it asked for.
            if current_age < max_age
                && has_conditional
                && !crate::helpers::stored_response::request_refuses_entry(
                    &tx.request.headers,
                    current_age,
                    max_age,
                )
            {
                return Some(ctx.report_with(&CONDITIONAL_REDUNDANT, format!(
                        "Request revalidated resource while response is still fresh (age {} < max-age {})",
                        current_age, max_age
                    )));
            }

            // The other side of the comparison was a second finding here: a stale
            // entry refetched with no conditional request though the stored
            // response carried a validator. That is `cached_validators_reused`'s
            // `conditional_missing`, and its gate is the wider one — it asks for a
            // validator on the previous response and no precondition on this
            // request, without consulting freshness at all, so every finding this
            // arm could make it makes already. What the freshness test added was
            // not a second defect but a narrower window on the same one.
            //
            // It also made a report this rule had no business making: with no
            // method gate, a POST re-request without an `If-None-Match` was
            // reported as a missed revalidation, where §13.1.2's SHOULD is written
            // about a GET and a POST's preconditions are `If-Match` and
            // `If-Unmodified-Since`.

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MaxAgeDirectiveValid;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction_with_response;
    use chrono::Utc;

    fn make_prev_with_headers(
        headers: &[(&str, &str)],
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = make_test_transaction_with_response(200, headers);
        prev.request.method = "GET".to_string();
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        prev.timestamp = ts;
        prev
    }

    /// **Early against what the client asked for.** A request that refuses the
    /// entry itself -- a browser's reload is `max-age=0`, a force reload
    /// `no-cache` -- asked for the round-trip this rule reports as wasted. An
    /// entry ten seconds into sixty: `max-age=30` and `min-fresh=50` it still
    /// meets, so those two revalidations were early.
    #[rstest::rstest]
    #[case(&[], true)]
    #[case(&[("cache-control", "max-age=0")], false)]
    #[case(&[("cache-control", "no-cache")], false)]
    #[case(&[("pragma", "no-cache")], false)]
    #[case(&[("cache-control", "max-age=30")], true)]
    #[case(&[("cache-control", "min-fresh=55")], false)]
    #[case(&[("cache-control", "min-fresh=50")], true)]
    fn a_request_that_refused_the_entry_asked_for_the_revalidation(
        #[case] request: &[(&str, &str)],
        #[case] expect_finding: bool,
    ) {
        let base = Utc::now();
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=60"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        let mut headers = vec![("if-none-match", "\"a\"")];
        headers.extend_from_slice(request);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &MaxAgeDirectiveValid,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert_eq!(v.is_some(), expect_finding, "{request:?} -> {v:?}");
    }

    /// The finding names the peer that wrote the precondition. A report read
    /// with `--about server` must not carry it, and one read with `--about
    /// client` must.
    #[test]
    fn the_finding_is_about_the_client_that_revalidated_early() {
        let rule = MaxAgeDirectiveValid;
        let base = chrono::Utc::now();
        let mut prev = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cache-control", "max-age=600"), ("etag", "\"v1\"")],
        );
        prev.request.method = "GET".to_string();
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        tx.request.method = "GET".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "conditional_redundant");
        assert_eq!(found.party, Some(crate::lint::Party::Client));
    }

    /// RFC 9111 § 4: the method a response answered has to allow it to be used
    /// for the request now presented. A stored `OPTIONS` is no entry for a `GET`
    /// and a stored `GET` is none for an `OPTIONS`, so on neither pairing did a
    /// client revalidate anything early — the origin answered because there was
    /// nothing to answer from.
    #[rstest::rstest]
    #[case("GET", "GET", true)]
    #[case("GET", "HEAD", true)]
    #[case("OPTIONS", "GET", false)]
    #[case("GET", "OPTIONS", false)]
    #[case("GET", "PUT", false)]
    fn an_entry_no_method_pairing_allows_was_not_revalidated_early(
        #[case] stored: &str,
        #[case] presented: &str,
        #[case] expect_finding: bool,
    ) {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();
        let mut prev = make_prev_with_headers(&[("cache-control", "max-age=600")], base);
        prev.request.method = stored.to_string();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.method = presented.to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert_eq!(v.is_some(), expect_finding, "{v:?}");
    }

    /// RFC 9111 § 4.1: the entry is stored for the variant the earlier request
    /// selected. A request presenting a different value for a field the response
    /// varies on could not have been answered from it, so its precondition
    /// revalidated nothing and cost nothing.
    #[rstest::rstest]
    #[case(None, None, true)]
    #[case(Some("gzip"), Some("gzip"), true)]
    #[case(None, Some("gzip"), false)]
    #[case(Some("gzip"), None, false)]
    #[case(Some("gzip"), Some("br"), false)]
    fn an_entry_stored_for_another_variant_was_not_revalidated_early(
        #[case] stored: Option<&str>,
        #[case] presented: Option<&str>,
        #[case] expect_finding: bool,
    ) {
        fn asked(e: Option<&str>, cond: bool) -> Vec<(&str, &str)> {
            let mut v: Vec<(&str, &str)> = e.map(|e| ("accept-encoding", e)).into_iter().collect();
            if cond {
                v.push(("if-none-match", "\"v1\""));
            }
            v
        }
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();
        let mut prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=600"),
                ("vary", "Accept-Encoding"),
            ],
            base,
        );
        prev.request.headers = crate::test_helpers::make_headers_from_pairs(&asked(stored, false));
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.method = "GET".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&asked(presented, true));
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert_eq!(v.is_some(), expect_finding, "{v:?}");
    }

    /// The pairing conditions are in the search, not after it, and this is the
    /// direction that says so: a response the pairing refuses must be stepped
    /// over rather than stopped at. A stored `OPTIONS` in front of a stored
    /// `GET` hid the entry the `GET` really did leave, so filtering without
    /// continuing the walk would trade a false positive for a false negative.
    #[test]
    fn a_refused_response_is_stepped_over_and_the_entry_behind_it_is_found() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();
        let older = make_prev_with_headers(&[("cache-control", "max-age=600")], base);
        let mut newer = make_prev_with_headers(
            &[("cache-control", "max-age=600")],
            base + chrono::Duration::seconds(1),
        );
        newer.request.method = "OPTIONS".to_string();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.method = "GET".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        // newest first, as the history contract requires.
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![newer, older]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        )
        .expect("the GET entry behind the OPTIONS");
        assert_eq!(v.violation, "conditional_redundant");
    }

    #[test]
    fn fresh_unconditional_no_violation() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(30);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none());
    }

    /// `age == max-age` is stale, so the freshness window has closed and there
    /// is nothing left for this rule to report — the unconditional half of this
    /// test asserted the finding that moved to `cached_validators_reused`.
    #[test]
    fn a_conditional_at_the_exact_boundary_is_not_early() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=10"), ("etag", "\"a\"")], base);

        // conditional at boundary should be permitted
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = crate::test_helpers::make_test_client();
        tx2.request.uri = "/resource".to_string();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx2.timestamp = base + chrono::Duration::seconds(10);
        let history2 =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx2,
                &history2,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "max_age_directive_valid"
                ]),
            )
            .is_none(),
            "conditional at boundary should not warn"
        );
    }

    /// The client's own write between the entry and the revalidation. A 2xx or
    /// 3xx to an unsafe method, or to one whose safety is unknown, invalidated
    /// the entry, so the revalidation was owed; an error answer, or a safe
    /// method, left the entry as it was.
    #[rstest::rstest]
    #[case("POST", 200, false)]
    #[case("PUT", 204, false)]
    #[case("POST", 303, false)]
    #[case("PURGE", 200, false)]
    #[case("POST", 403, true)]
    #[case("DELETE", 500, true)]
    #[case("OPTIONS", 200, true)]
    fn a_write_between_decides_whether_the_entry_is_still_held(
        #[case] method: &str,
        #[case] status: u16,
        #[case] reported: bool,
    ) {
        let base = Utc::now();
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=60"), ("etag", "\"a\"")], base);
        let mut write = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        write.client = crate::test_helpers::make_test_client();
        write.request.method = method.to_string();
        write.request.uri = "/resource".to_string();
        write.timestamp = base + chrono::Duration::seconds(5);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(304, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![write, prev]);
        let v = crate::test_helpers::run_rule(
            &MaxAgeDirectiveValid,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert_eq!(
            v.as_ref().map(|v| v.violation.as_str()),
            reported.then_some("conditional_redundant"),
            "{method} -> {status}"
        );
    }

    #[test]
    fn fresh_conditional_reports_violation() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=60"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "conditional_redundant");
        assert!(v.message.contains("still fresh"), "{}", v.message);
    }

    #[test]
    fn stale_conditional_is_ok() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=1"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none());
    }

    /// A stale entry refetched without a conditional request is
    /// `cached_validators_reused`'s finding, from the same evidence and with a
    /// wider gate — it asks for a validator on the stored response and no
    /// precondition on this request, and never consults freshness. This rule
    /// stopped making it.
    #[test]
    fn a_stale_refetch_belongs_to_the_validator_rule() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=1"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn stale_unconditional_no_violation_without_validator() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "max-age=1")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_max_age_skips() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "no-store")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn max_age_ignored_when_no_cache_or_no_store() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // previous response had max-age but also no-cache, should be ignored
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, no-cache")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(
            v.is_none(),
            "max-age should be ignored when no-cache present"
        );
    }

    #[test]
    fn age_header_affects_freshness() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // age header 10 + elapsed 30 = 40 < max-age 100
        let prev = make_prev_with_headers(&[("cache-control", "max-age=100"), ("age", "10")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(30);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_some(), "expected violation because still fresh");
    }

    /// The `Age` seeding still decides freshness, which is what this pins now
    /// that the stale half is another rule's: 15 seconds of stored age against
    /// a `max-age` of 10 closes the window, so a request arriving with no
    /// precondition is nothing this rule has to say.
    #[test]
    fn the_age_header_closes_the_window() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // age header 15 + elapsed 0 = 15 > max-age 10
        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=10"),
                ("age", "15"),
                ("etag", "\"a\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base;

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn max_age_zero_behaviour() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // zero max-age means freshness lifetime is immediate
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=0"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base;
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]);
        // `age == max-age` is stale, so there is no freshness window at all and
        // neither request below is early. The unconditional one used to be
        // reported here; it is `cached_validators_reused`'s.
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none(), "{v:?}");

        // conditional at same moment is appropriate (entry stale) and should NOT trigger a violation
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = crate::test_helpers::make_test_client();
        tx2.request.uri = "/resource".to_string();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx2.timestamp = base;
        let history2 =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx2,
                &history2,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "max_age_directive_valid"
                ]),
            )
            .is_none(),
            "conditional at boundary should not warn"
        );
    }

    #[test]
    fn negative_elapsed_is_clamped() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // transaction timestamp earlier than prev
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=5"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base - chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        // age computed from elapsed clamped to 0 yields fresh state; no violation expected
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn cache_control_max_age_helper_tests() {
        use crate::helpers::cache_control::get_cache_control_max_age;

        // no header
        let mut hm = hyper::HeaderMap::new();
        assert!(get_cache_control_max_age(&hm).is_none());

        hm.append("cache-control", "max-age=30".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(30));

        // multiple directives (extensions allowed), comma and semicolon should both work
        hm.clear();
        hm.append("cache-control", "private, max-age=5".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(5));

        // invalid number
        hm.clear();
        hm.append("cache-control", "max-age=abc".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());

        // negative value not allowed
        hm.clear();
        hm.append("cache-control", "max-age=-1".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());

        // explicit directives that forbid caching result in None
        hm.clear();
        hm.append("cache-control", "max-age=30, no-store".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());
        hm.clear();
        hm.append("cache-control", "no-cache, max-age=30".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());

        // directive name is case-insensitive
        hm.clear();
        hm.append("cache-control", "Max-Age=7".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(7));
        hm.clear();
        hm.append("cache-control", "MAX-AGE=8".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(8));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "max_age_directive_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
