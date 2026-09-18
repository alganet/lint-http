// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Ensure that responses for a given resource do not regress in their
/// representation date.  This is a heuristic, not a direct spec check: RFC 9111
/// §4.2.4 forbids a cache from generating a *stale* response, but it defines
/// "stale" against the §4.2 freshness calculation, which this rule performs
/// only where the response carries its terms — and where it does, the
/// arithmetic decides: a response whose lifetime exceeds its age is fresh and
/// is not reported, whatever its representation time says against the
/// history.  Elsewhere we approximate the observable symptom — a later response
/// carrying an older representation timestamp than one already seen for the
/// same URI — by computing a simple timestamp from the `Last-Modified` header
/// (RFC 9110 §8.8.2, the representation's own modification time) or, failing
/// that, the `Date` header (RFC 9110 §6.6.1, only the message's origination
/// time, a coarser proxy).  The two are compared only with themselves — a
/// `Last-Modified` read against a `Date` reports staleness that is an artefact
/// of which headers the pair of responses carried rather than of the traffic,
/// for the reason the private `Clock` type records.  Only a GET or HEAD
/// response that carries the resource is read at all — see
/// `dates_the_resource`.  The engine keys the history it hands this rule on the
/// client and the request target; the method and the Vary secondary key are
/// read off each entry, by `dates_the_resource` and
/// `selects_the_same_representation`.  What the key still misses is a validator
/// such as `ETag`, so two representations one origin distinguishes and `Vary`
/// does not are read as one.
pub struct CacheCoherence;

/// Which of two clocks a representation time was read off.
///
/// They are never compared with one another. `Last-Modified` names when the
/// origin believes the representation was edited; `Date` names when it
/// originated the message carrying it. For any one response the first is at or
/// before the second — a server cannot describe a representation before it has
/// one — so reading a later response's `Last-Modified` against an earlier
/// response's `Date` compares a smaller number with a larger one for reasons
/// that have nothing to do with staleness. Two responses for an unchanged page,
/// one of which happens not to advertise its modification time, are enough to
/// produce it.
///
/// Keeping the clocks apart costs nothing the rule was entitled to: the maximum
/// within one clock is a maximum over a subset, so every finding that survives
/// is one the mixed comparison also made.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Clock {
    /// `Last-Modified` — the representation's own edit time, and the signal the
    /// rule is really after: a decrease is the representation going backwards.
    Representation,
    /// `Date` — the message's origination time, the coarser fallback used only
    /// when a response times nothing else.
    Message,
}

/// Whether a response times the *target resource* rather than the exchange
/// that asked for it. Both halves of the question have to be asked, because a
/// 200 is not one answer: § 15.3.1 tabulates six, one per method.
///
/// **The status.** A 200 carries the resource and so does a 206, which
/// transfers parts of the very same selected representation. Nothing else
/// does: a 3xx describes where to go next, a 4xx or 5xx describes what went
/// wrong, and a 204 or a 304 carries no representation at all. Those are
/// generated when the request arrives, so their `Date` is the moment of asking
/// — while a cache hit for the resource legitimately carries the *stored*
/// response's `Date`, which is older by design.
///
/// **The method.** Even at 200 the content is a representation of the target
/// resource only for GET and, per § 4.3.5 of the caching specification,
/// for the HEAD that would have been that GET without the body. Answering
/// OPTIONS it represents the communication options, answering TRACE it is a
/// copy of our own request, answering POST or PUT it is the status of the
/// action. None of those has a modification time the resource owns, and none
/// of them shares a cache entry with the GET: reading their `Date` as the
/// resource's is the same category error as reading a 304's.
///
/// Letting either kind onto the timeline poisons it: a single conditional
/// request answered `304`, or one `TRACE` refused with `405`, or one `OPTIONS`
/// answered now, raises the maximum to *now*, and every subsequent cache hit
/// for the resource reads as a representation that went backwards. That is not
/// a stale response, it is two different kinds of message read off one clock.
///
/// The rule already declined to *report* on a 304 for exactly this reason. The
/// same sentence rules it out as something to report *against*.
fn dates_the_resource(method: &str, status: u16) -> bool {
    // cite(RFC 9110 § 15.3.1): "The content sent in a 200 response depends on the request method."
    // cite(RFC 9111 § 4.3.5): "A response to the HEAD method is identical to what an equivalent request made with a GET would have been, without sending the content."
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    // cite(RFC 9110 § 15.3.7): "The 206 (Partial Content) status code indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation."
    // cite(RFC 9110 § 15.4.5): "there is no need for the server to transfer a representation of the target resource because the request indicates that the client, which made the request conditional, already has a valid representation"
    // cite(RFC 9110 § 15.5): "Except when responding to a HEAD request, the server SHOULD send a representation containing an explanation of the error situation, and whether it is a temporary or permanent condition."
    matches!(status, 200 | 206)
}

/// Whether the stored response's `Vary` lets these two requests read the same
/// entry — that is, whether the two responses are timestamps of one selected
/// representation or of two.
///
/// `Vary` is the cache key's second half. A response that nominates
/// `Accept-Encoding` is stored once per encoding, and the compressed variant of
/// a page carrying a `Last-Modified` a few seconds apart from the identity one
/// is two files built at two moments, not one file that went backwards. The
/// rule reported that difference as a stale response, on origins that were
/// serving both variants correctly.
///
/// The question is § 4's, asked of every reader that pairs a stored response
/// with a later request, so the reading lives with the other conditions on
/// that pairing in [`crate::helpers::stored_response`]; what it tolerates,
/// and why the strict direction is the right one, is written there.
fn selects_the_same_representation(
    stored: &crate::http_transaction::ResponseInfo,
    stored_request: &hyper::HeaderMap,
    presented: &hyper::HeaderMap,
) -> bool {
    crate::helpers::stored_response::selecting_fields_match(
        stored_request,
        &stored.headers,
        presented,
    )
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
use crate::violations::cache::{CACHE_RESPONSE_CONFLICTING, RFC_9111_4_2, RFC_9111_4_2_4};
use crate::violations::ViolationDef;

/// One entry, and it belongs to a subject about caches rather than about
/// fields: what this rule sees is two responses disagreeing, and § 4.2.4's
/// MUST NOT is what makes that disagreement worth reporting.
static DECLARED: &[&ViolationDef] = &[&CACHE_RESPONSE_CONFLICTING];
const RFC_9110_8_8_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
    note: "Last-Modified — the representation's modification time (preferred signal)",
};
const RFC_9110_6_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("6.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1",
    note: "Date — the message's origination time (coarser fallback signal)",
};
const RFC_9111_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Vary — the cache key's second half, so two variants are two timelines",
};
const RFC_9110_15_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1",
    note: "200 OK — what its content represents depends on the request method",
};
const RFC_9111_4_3_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.5",
    note: "HEAD answers as the GET would have, so it dates the same resource",
};
const RFC_9110_15_3_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7",
    note: "206 Partial Content — parts of the same selected representation, so it dates it",
};
const RFC_9110_15_4_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
    note: "304 Not Modified — conveys no representation, so it dates nothing",
};
const RFC_9110_15_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5",
    note: "4xx Client Error — the representation explains the error, not the resource",
};

impl RuleMeta for CacheCoherence {
    fn id(&self) -> &'static str {
        "cache_coherence"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Cache coherence ensures that once a newer representation of a resource is\navailable, earlier (stale) copies are not inadvertently served without\nrevalidation or invalidation.  Misconfigured caches or origin servers may\nreturn an older version of a document after a newer one has been observed.\n\nThis rule reconstructs a simple timeline for each resource observed by the\nclient.  Each response is assigned a timestamp derived from its\n`Last-Modified` header if present, otherwise from the `Date` header.  If a\nsubsequent response for the *same URI* carries a timestamp that is strictly\nolder than one seen previously *on that same header*, we report a violation —\nthe later response appears to be serving a stale representation.\n\nThe two headers are never compared with each other.  `Last-Modified` is when\nthe representation was edited and `Date` is when the message was sent, so the\nfirst is at or before the second in any one response; comparing across them\nreports a page whose siblings simply omit `Last-Modified` as stale.\n\nOnly transactions whose response contains a parseable HTTP-date are\nexamined; missing or unparseable headers are ignored.  Only a 200 or a 206\nanswering a GET or a HEAD joins the timeline, on either side of the\ncomparison.  Those carry the resource; a 3xx, a 4xx, a 5xx, a 204 or a 304\nis generated when the request arrives and so dates the asking, and even a\n200 represents the communication options rather than the resource when it\nanswers an OPTIONS, or our own request when it answers a TRACE.  Reading\none of those as a previous observation raises the timeline to *now* and\nreports every later cache hit — which correctly carries the stored\nresponse's older Date — as stale.\n\nA previous response is compared only when its `Vary` nominates nothing the\ntwo requests wrote differently.  Two encodings of one page are two stored\nentries, and the timestamps of one say nothing about the freshness of the\nother.\n\nA response that carries the terms of §4.2's definition is judged by the\ndefinition rather than by the timeline.  Where `max-age`, `s-maxage` or\n`Expires` gives a freshness lifetime and `Age` or `Date` gives a current\nage, a lifetime that exceeds the age makes the response fresh, and a fresh\nresponse is one every cache on the path was permitted to serve — a cache\nhit under `max-age=600` with `Age: 31` is not stale because a sibling node\nhanded over a newer copy five seconds earlier.  Such a response is not\nreported.  One whose age has run past its lifetime, or one that advertises\nno lifetime at all, is reported by the timeline as before."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_4_2_4,
            RFC_9111_4_2,
            RFC_9111_4_1,
            RFC_9110_8_8_2,
            RFC_9110_6_6_1,
            RFC_9110_15_3_1,
            RFC_9111_4_3_5,
            RFC_9110_15_3_7,
            RFC_9110_15_4_5,
            RFC_9110_15_5,
        ]
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
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Date: Wed, 21 Oct 2015 07:28:00 GMT\n\n> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Date: Wed, 21 Oct 2015 08:28:00 GMT",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— using `Last-Modified`"),
                snippet: "< HTTP/1.1 200 OK\n< Last-Modified: Wed, 21 Oct 2015 08:28:00 GMT\n\n< HTTP/1.1 200 OK\n< Last-Modified: Wed, 21 Oct 2015 09:00:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— out‑of‑order `Date`"),
                snippet: "< HTTP/1.1 200 OK\n< Date: Wed, 21 Oct 2015 08:28:00 GMT\n\n< HTTP/1.1 200 OK\n< Date: Wed, 21 Oct 2015 07:28:00 GMT    # older than previous",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `Last-Modified` decreases"),
                snippet: "< HTTP/1.1 200 OK\n< Last-Modified: Wed, 21 Oct 2015 08:28:00 GMT\n\n< HTTP/1.1 200 OK\n< Last-Modified: Wed, 21 Oct 2015 07:00:00 GMT    # stale copy",
            },
        ]
    }
}

impl Rule for CacheCoherence {
    fn needs_response(&self) -> bool {
        // the rule only inspects server responses; request headers are used
        // to identify the resource but nothing else is required.
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;

            // Only a response that carries the resource itself belongs on the
            // timeline — as the message being judged and as one it is judged
            // against.
            if !dates_the_resource(&tx.request.method, resp.status) {
                return None;
            }

            // helper to extract a "representation time" from headers.  We prefer
            // Last-Modified but fall back to Date.  Return None if neither can be
            // parsed.
            fn rep_time(
                headers: &hyper::HeaderMap,
            ) -> Option<(chrono::DateTime<chrono::Utc>, Clock)> {
                // Prefer Last-Modified: it timestamps the *representation* itself, so
                // a decrease directly signals the representation went backwards. The
                // HTTP-date grammar is owned by the parse helper (§5.6.7).
                // cite(RFC 9110 § 8.8.2): "The "Last-Modified" header field in a response provides a timestamp indicating the date and time at which the origin server believes the selected representation was last modified"
                if let Some(hv) = headers.get("last-modified") {
                    if let Ok(s) = hv.to_str() {
                        if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                            return Some((dt, Clock::Representation));
                        }
                    }
                }
                // Date is only the *message's* origination time, not the
                // representation's — a coarser proxy, and the source of this rule's
                // heuristic nature: a fresh response may legitimately carry a Date
                // earlier than a prior message for the same URI, which this rule
                // cannot distinguish from a genuine regression.
                // cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated"
                if let Some(hv) = headers.get("date") {
                    if let Ok(s) = hv.to_str() {
                        if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                            return Some((dt, Clock::Message));
                        }
                    }
                }
                None
            }

            let (curr_time, curr_clock) = rep_time(&resp.headers)?; // nothing we can compare

            // Scan previous history entries for the same URI and track the largest
            // timestamp read off THE SAME CLOCK, which is the only comparison that
            // means anything: see `Clock`.
            let mut max_prev: Option<chrono::DateTime<chrono::Utc>> = None;
            for (prev, prev_resp) in history.responses() {
                // The URI half of the cache key is the engine's: this rule is
                // registered `ByResource`, so every entry here already has this
                // client and this request target. The rule used to test it again,
                // which was a test that could not be false. The method and the
                // Vary secondary key are the rest of the key, and both are read
                // off the entry below.
                if !dates_the_resource(&prev.request.method, prev_resp.status) {
                    continue;
                }
                if !selects_the_same_representation(
                    prev_resp,
                    &prev.request.headers,
                    &tx.request.headers,
                ) {
                    continue;
                }
                if let Some((t, prev_clock)) = rep_time(&prev_resp.headers) {
                    if prev_clock != curr_clock {
                        continue;
                    }
                    max_prev = Some(match max_prev {
                        Some(existing) => std::cmp::max(existing, t),
                        None => t,
                    });
                }
            }

            // A representation going backwards in time across two responses is the observable
            // form of a cache serving something it should have revalidated. §4.2.4's MUST NOT
            // is the requirement this heuristic stands in for: we cannot compute §4.2 freshness
            // (no age or lifetime here), so a strictly-older timestamp is our proxy for "stale".
            // cite(RFC 9111 § 4.2.4): "A cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly permitted by the client or origin server"
            if let Some(prev_max) = max_prev {
                if curr_time < prev_max {
                    // The shape is only a stand-in for the definition, and a response
                    // that carries the definition's terms is judged by them. A cache hit
                    // under `max-age=600` with `Age: 31` is fresh, and a fresh response
                    // is exactly what § 4.2.4 permits a cache to serve — however much
                    // newer the representation a sibling node handed over moments
                    // before. Only a response past its lifetime, or one that states no
                    // lifetime at all, is left for the shape to describe.
                    // cite(RFC 9111 § 4.2): "response_is_fresh = (freshness_lifetime > current_age)"
                    if crate::helpers::cache_control::fresh_when_observed(
                        &resp.headers,
                        tx.timestamp,
                    ) {
                        return None;
                    }
                    return Some(ctx.report_with(
                        &CACHE_RESPONSE_CONFLICTING,
                        format!(
                            "response for '{}' appears stale ({} < previous {})",
                            tx.request.uri, curr_time, prev_max
                        ),
                    ));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheCoherence;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resp_tx(
        uri: &str,
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.uri = uri.to_string();
        tx
    }

    /// The same, for the Vary dimension: what the request wrote matters only
    /// when the stored response nominated the field.
    fn make_negotiated_tx(
        uri: &str,
        req_headers: &[(&str, &str)],
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_resp_tx(uri, status, headers);
        for (name, value) in req_headers {
            tx.request.headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        tx
    }

    /// The same, for the method dimension: `make_resp_tx` answers a GET.
    fn make_method_tx(
        method: &str,
        uri: &str,
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_resp_tx(uri, status, headers);
        tx.request.method = method.to_string();
        tx
    }

    #[test]
    fn no_violation_without_history() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(&rule, &tx, &history, &cfg).is_none());
    }

    #[test]
    fn increasing_date_ok() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 08:28:00 GMT")],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg,).is_none());
    }

    #[test]
    fn out_of_order_date_flagged() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 08:28:00 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.violation, "cache_response_conflicting");
        assert!(v.message.contains("appears stale"));
    }

    #[test]
    fn last_modified_decrease_flagged() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Wed, 21 Oct 2015 08:28:00 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert!(v.is_some());
    }

    /// The shape a multi-node CDN serves for a page whose modification time is
    /// its generation time: one node misses and hands over a copy stamped
    /// *now*, and five seconds later a sibling node hits on the copy it stored
    /// half a minute ago. The representation went backwards on the wire and
    /// nothing was served stale: the hit carries `max-age=600` and `Age: 31`,
    /// so § 4.2's arithmetic makes it fresh, and a fresh response is one
    /// every cache on the path was permitted to serve.
    #[test]
    fn a_fresh_hit_behind_a_newer_miss_is_not_stale() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let miss = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT"),
                ("cache-control", "max-age=600, must-revalidate"),
            ],
        );
        let mut hit = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT"),
                ("cache-control", "max-age=600, must-revalidate"),
                ("age", "31"),
            ],
        );
        hit.timestamp = miss.timestamp + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![miss]);
        assert!(crate::test_helpers::run_rule(&rule, &hit, &history, &cfg).is_none());
    }

    /// The same hit once its lifetime has run out is what the definition calls
    /// stale, and the timeline is allowed to say so.
    #[test]
    fn a_hit_past_its_lifetime_behind_a_newer_miss_is_stale() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let miss = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT"),
                ("cache-control", "max-age=600, must-revalidate"),
            ],
        );
        let mut hit = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT"),
                ("cache-control", "max-age=600, must-revalidate"),
                ("age", "700"),
            ],
        );
        hit.timestamp = miss.timestamp + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![miss]);
        let v = crate::test_helpers::run_rule(&rule, &hit, &history, &cfg);
        assert_eq!(
            v.map(|v| v.violation).as_deref(),
            Some("cache_response_conflicting")
        );
    }

    /// A lifetime the response gives only to a shared cache is a lifetime
    /// some conforming cache served it under; and a lifetime a bare
    /// `no-cache` withdraws is no lifetime, so the shape decides again.
    #[test]
    fn the_lifetime_read_is_any_a_conforming_cache_could_use() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        for (cache_control, expected_silent) in [
            ("max-age=0, s-maxage=600", true),
            ("no-cache, max-age=600", false),
        ] {
            let miss = make_resp_tx(
                "https://example.com/foo",
                200,
                &[
                    ("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT"),
                    ("cache-control", cache_control),
                ],
            );
            let mut hit = make_resp_tx(
                "https://example.com/foo",
                200,
                &[
                    ("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT"),
                    ("cache-control", cache_control),
                    ("age", "31"),
                ],
            );
            hit.timestamp = miss.timestamp + chrono::Duration::seconds(5);
            let history =
                crate::transaction_history::TransactionHistory::from_transactions(vec![miss]);
            assert_eq!(
                crate::test_helpers::run_rule(&rule, &hit, &history, &cfg).is_none(),
                expected_silent,
                "under `{cache_control}`"
            );
        }
    }

    /// The `Date` clock under the same definition: a hit whose `Date` sits
    /// below the previous one and whose `Age` has run past a `max-age=0` is
    /// stale by arithmetic as well as by shape, and still reports.
    #[test]
    fn a_date_that_descends_past_a_zero_lifetime_is_stale() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("date", "Sun, 30 Aug 2026 01:12:53 GMT"),
                ("cache-control", "public, max-age=0, must-revalidate"),
                ("age", "329"),
            ],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("date", "Sun, 30 Aug 2026 01:12:41 GMT"),
                ("cache-control", "public, max-age=0, must-revalidate"),
                ("age", "350"),
            ],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(9);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert_eq!(
            v.map(|v| v.violation).as_deref(),
            Some("cache_response_conflicting")
        );
    }

    /// The shape a real origin serves: one unchanging page, fetched three
    /// times, where the middle response happens to omit `Last-Modified`. Its
    /// `Date` is *now* and the page's edit time is months back, so a rule that
    /// compares the two clocks reports the third response — byte-identical to
    /// the first — as stale.
    #[test]
    fn last_modified_under_a_sibling_date_is_not_a_regression() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let edited = "Tue, 16 Jun 2026 14:44:29 GMT";
        let first = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", edited),
                ("date", "Sat, 29 Aug 2026 23:57:49 GMT"),
            ],
        );
        // Same page, same hop-visible content, but this response times only
        // itself: its Date is the newest number either header has produced.
        let mut bare = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Sat, 29 Aug 2026 23:57:53 GMT")],
        );
        bare.timestamp = first.timestamp + chrono::Duration::seconds(1);
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("last-modified", edited),
                ("date", "Sat, 29 Aug 2026 23:57:54 GMT"),
            ],
        );
        curr.timestamp = first.timestamp + chrono::Duration::seconds(2);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![bare, first]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none());
    }

    /// The clocks are kept apart, not silenced: a `Last-Modified` that descends
    /// against another `Last-Modified` still reports, even with a later `Date`
    /// standing between them.
    #[test]
    fn last_modified_decrease_flagged_across_a_bare_sibling() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let first = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT")],
        );
        let mut bare = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Sun, 30 Aug 2026 01:40:00 GMT")],
        );
        bare.timestamp = first.timestamp + chrono::Duration::seconds(1);
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT")],
        );
        curr.timestamp = first.timestamp + chrono::Duration::seconds(2);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![bare, first]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert!(v.is_some());
        assert_eq!(v.unwrap().violation, "cache_response_conflicting");
    }

    /// The shape a CDN serves all day: a cache hit whose `Date` is the stored
    /// response's, with one conditional request answered `304` standing between
    /// two of them. The 304 was generated on the spot, so its `Date` is *now* —
    /// and reading it as a previous observation makes the next hit, a byte for
    /// byte identical response, the one that went backwards.
    #[test]
    fn a_304_between_two_hits_is_not_the_resource_going_backwards() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let stored = "Sat, 29 Aug 2026 23:57:32 GMT";
        let hit = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
        let mut revalidated = make_resp_tx(
            "https://example.com/foo",
            304,
            &[("date", "Sun, 30 Aug 2026 00:02:09 GMT")],
        );
        revalidated.timestamp = hit.timestamp + chrono::Duration::seconds(1);
        let mut curr = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
        curr.timestamp = hit.timestamp + chrono::Duration::seconds(2);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            revalidated,
            hit,
        ]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none());
    }

    /// A conditional request the origin refused with `412`, or a `TRACE` it
    /// refused with `405`, dates the refusal. Neither says the resource is
    /// newer than the copy the cache is still serving.
    #[test]
    fn a_refusal_does_not_date_the_resource() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        for refused in [405u16, 412, 416, 404, 204, 302] {
            let stored = "Sun, 30 Aug 2026 01:12:41 GMT";
            let hit = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
            let mut declined = make_resp_tx(
                "https://example.com/foo",
                refused,
                &[("date", "Sun, 30 Aug 2026 01:18:28 GMT")],
            );
            declined.timestamp = hit.timestamp + chrono::Duration::seconds(1);
            let mut curr = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
            curr.timestamp = hit.timestamp + chrono::Duration::seconds(2);
            let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
                declined, hit,
            ]);
            assert!(
                crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none(),
                "a {refused} in history was read as the resource moving forward"
            );
        }
    }

    /// The other side of the same reading: a response that only explains why
    /// the request failed is not itself a representation that went backwards,
    /// however old its `Date` is against the hits around it.
    #[test]
    fn a_refusal_is_not_a_representation_that_regressed() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let hit = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Sun, 30 Aug 2026 01:41:18 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            416,
            &[("date", "Sun, 30 Aug 2026 01:41:17 GMT")],
        );
        curr.timestamp = hit.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![hit]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none());
    }

    /// A `206` transfers parts of the very same selected representation, so it
    /// stays on the timeline on both sides of the comparison.
    #[test]
    fn a_206_still_dates_the_representation() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Sun, 30 Aug 2026 01:30:13 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            206,
            &[("last-modified", "Sun, 30 Aug 2026 01:30:05 GMT")],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert_eq!(v.unwrap().violation, "cache_response_conflicting");
    }

    /// A 200 to OPTIONS represents the communication options and a 200 to TRACE
    /// is a copy of the request that asked for it. Both are written when the
    /// request arrives, so both date the asking, and neither is the resource
    /// the cache hits around them are serving.
    #[test]
    fn a_200_to_another_method_does_not_date_the_resource() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        for method in ["OPTIONS", "TRACE", "POST", "PUT"] {
            let stored = "Sat, 29 Aug 2026 23:57:32 GMT";
            let hit = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
            let mut aside = make_method_tx(
                method,
                "https://example.com/foo",
                200,
                &[("date", "Sun, 30 Aug 2026 00:02:09 GMT")],
            );
            aside.timestamp = hit.timestamp + chrono::Duration::seconds(1);
            let mut curr = make_resp_tx("https://example.com/foo", 200, &[("date", stored)]);
            curr.timestamp = hit.timestamp + chrono::Duration::seconds(2);
            let history =
                crate::transaction_history::TransactionHistory::from_transactions(vec![aside, hit]);
            assert!(
                crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none(),
                "a 200 to {method} was read as the resource moving forward"
            );
        }
    }

    /// And the other side of it: an `OPTIONS` answered from an older clock than
    /// the GET beside it is not the resource regressing, so it is not reported.
    #[test]
    fn a_200_to_another_method_is_not_a_representation_that_regressed() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let hit = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Sun, 30 Aug 2026 01:12:53 GMT")],
        );
        let mut curr = make_method_tx(
            "OPTIONS",
            "https://example.com/foo",
            200,
            &[("date", "Sun, 30 Aug 2026 01:07:09 GMT")],
        );
        curr.timestamp = hit.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![hit]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none());
    }

    /// HEAD is the exception the caching specification names: it answers as the
    /// GET would have, so it stays on the resource's timeline on both sides.
    #[test]
    fn a_head_dates_the_same_resource_as_the_get() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_method_tx(
            "HEAD",
            "https://example.com/foo",
            200,
            &[("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT")],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT")],
        );
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert_eq!(v.unwrap().violation, "cache_response_conflicting");
    }

    /// A page served under `Vary: Accept-Encoding` is stored once per encoding.
    /// Its compressed variant carrying a `Last-Modified` seconds apart from the
    /// identity one is two files built at two moments, not one file that went
    /// backwards, and the two timelines do not meet.
    #[test]
    fn two_variants_of_one_page_are_two_timelines() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let identity = make_negotiated_tx(
            "https://example.com/foo",
            &[],
            200,
            &[
                ("vary", "Accept-Encoding"),
                ("last-modified", "Sun, 30 Aug 2026 01:30:13 GMT"),
            ],
        );
        let mut compressed = make_negotiated_tx(
            "https://example.com/foo",
            &[("accept-encoding", "gzip, br, identity;q=0")],
            200,
            &[
                ("vary", "Accept-Encoding"),
                ("last-modified", "Sun, 30 Aug 2026 01:30:05 GMT"),
            ],
        );
        compressed.timestamp = identity.timestamp + chrono::Duration::seconds(1);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![identity]);
        assert!(crate::test_helpers::run_rule(&rule, &compressed, &history, &cfg).is_none());
    }

    /// The nomination is what decides it, not the presence of `Vary`: a response
    /// that varies on a field neither request wrote is one entry, and a
    /// regression across it is still a regression.
    #[test]
    fn a_vary_on_a_field_neither_request_wrote_is_still_one_timeline() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let first = make_negotiated_tx(
            "https://example.com/foo",
            &[],
            200,
            &[
                ("vary", "rsc, next-router-prefetch"),
                ("date", "Sun, 30 Aug 2026 01:12:53 GMT"),
            ],
        );
        let mut curr = make_negotiated_tx(
            "https://example.com/foo",
            &[("accept-encoding", "gzip")],
            200,
            &[
                ("vary", "rsc, next-router-prefetch"),
                ("date", "Sun, 30 Aug 2026 01:12:41 GMT"),
            ],
        );
        curr.timestamp = first.timestamp + chrono::Duration::seconds(1);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![first]);
        let v = crate::test_helpers::run_rule(&rule, &curr, &history, &cfg);
        assert_eq!(v.unwrap().violation, "cache_response_conflicting");
    }

    /// `Vary: *` never matches, so nothing is ever compared against a response
    /// that sent one, however alike the two requests look.
    #[test]
    fn a_wildcard_vary_matches_nothing() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let first = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("vary", "*"),
                ("last-modified", "Sun, 30 Aug 2026 01:36:09 GMT"),
            ],
        );
        let mut curr = make_resp_tx(
            "https://example.com/foo",
            200,
            &[
                ("vary", "*"),
                ("last-modified", "Sun, 30 Aug 2026 01:35:43 GMT"),
            ],
        );
        curr.timestamp = first.timestamp + chrono::Duration::seconds(1);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![first]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg).is_none());
    }

    #[test]
    fn no_time_headers_no_violation() {
        let rule = CacheCoherence;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let prev = make_resp_tx("https://example.com/foo", 200, &[]);
        let mut curr = make_resp_tx("https://example.com/foo", 200, &[]);
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(&rule, &curr, &history, &cfg,).is_none());
    }

    /// The rule reads `history` without re-testing the request target, because
    /// the engine has already keyed it. This is the registration that makes that
    /// true; if it ever changed, the rule would start comparing one resource's
    /// timeline against another's and say nothing about it.
    #[test]
    fn history_is_keyed_on_the_request_target() {
        assert_eq!(
            crate::rules::query_type_for(CacheCoherence.id()),
            Some(crate::queries::QueryType::ByResource)
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cache_coherence");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
