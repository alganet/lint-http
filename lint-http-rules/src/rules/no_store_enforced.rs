// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_NO_STORE_IGNORED, RFC_9111_5_2_2_5};
use crate::violations::ViolationDef;

/// One entry, and two ways of noticing it: a validator kept from a response
/// the directive said to keep no part of.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_NO_STORE_IGNORED];

/// Ensure that responses marked `no-store` are never reused for later
/// conditional requests.  The `no-store` directive (RFC 9111 §5.2.2.5) tells
/// caches that they must not retain any part of the response; if a later
/// request for the same resource carries a validator (ETag or Last-Modified)
/// matching a previously observed `no-store` response, that is evidence the
/// entry was stored in violation of the directive.
///
/// **Ordering note:** this rule inspects the provided transaction history
/// in recency order so that the "most recent occurrence wins" semantics are
/// applied.  The `TransactionHistory` type is intended to supply entries
/// newest-first, and we additionally sort by timestamp in the check to
/// protect against callers passing an unsorted vector.  See
/// `check_transaction` for details.
///
/// This stateful rule looks back through the transaction history for any
/// prior responses with a `no-store` Cache-Control directive.  It tracks the
/// most recent appearance of each validator value and remembers whether that
/// appearance was paired with `no-store`.  When the current request presents a
/// conditional header that references one of those "no-store" validators, the
/// rule emits a violation.
///
/// The check only applies to histories scoped by resource (i.e. transactions
/// for the same client+URI); the engine ensures unrelated exchanges are
/// filtered out.
pub struct NoStoreEnforced;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3",
    note: "Validation (conditional requests carry the validators this rule tracks)",
};

impl RuleMeta for NoStoreEnforced {
    fn id(&self) -> &'static str {
        "no_store_enforced"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful no-store enforcement")
    }

    fn description(&self) -> &'static str {
        "The `no-store` cache-control directive (RFC 9111 §5.2.2.5) tells caches that **they must not retain any part of the response or request**.  A cache that breaks this rule may later reuse stale or private data inappropriately.\n\nThis stateful rule observes the history of a particular client+resource and remembers which validator values (ETag or Last-Modified) were seen on responses that carried `Cache-Control: no-store`.  A validator counts as forbidden only if **no** exchange the client was allowed to store ever offered it. The most recent occurrence used to decide, and that read a `max-age=60` response handing over `ETag: \"a\"` and a later `no-store` response carrying the same tag as a client stealing what it had been licensed to keep: §5.2.2.5 forbids storing *that* response and evicts nothing already held. So the sets are subtracted rather than raced, and \"allowed to store\" counts the directive on the earlier request (§5.2.1.5) as well as the one on its response. `Last-Modified` values are subtracted by both spelling and instant, since the match below compares both.  When the current request carries a conditional header whose value matches one of those \"no-store\" validators, we infer that the response must have been stored at some point, and a violation is reported.\n\nThe check is scoped to resource histories (the engine filters transactions by URI) and therefore does not attempt to reason about unrelated traffic.  The rule does not flag unconditional requests, nor does it attempt to detect improper storage of requests (which is rarely visible from traffic capture)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2_2_5, RFC_9111_4_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// examine both requests and previous responses for the resource
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— no reuse"),
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-store\n< ETag: \"a\"\n\n# later the client issues a fresh request with no conditional headers;\n# since there is nothing to compare the rule does not fire.\n> GET /foo HTTP/1.1\n> Host: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— validator later refreshed without no-store"),
                snippet: "< HTTP/1.1 200 OK\n< Cache-Control: no-store\n< ETag: \"a\"\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n< ETag: \"a\"\n\n> GET /foo HTTP/1.1\n> Host: example.com\n> If-None-Match: \"a\"    # this value now comes from a cacheable response",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— conditional request referencing a no-store response"),
                snippet: "< HTTP/1.1 200 OK\n< Cache-Control: no-store\n< ETag: \"x\"\n\n> GET /foo HTTP/1.1\n> Host: example.com\n> If-None-Match: \"x\"    # validator derived from a no-store entry",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— conditional request referencing a no-store response"),
                snippet: "< HTTP/1.1 200 OK\n< Cache-Control: no-store\n< Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\n\n> GET /foo HTTP/1.1\n> Host: example.com\n> If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT",
            },
        ]
    }
}

impl Rule for NoStoreEnforced {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Which validators the client could only have got by storing what
            // it was told not to store.
            //
            // **A validator any storable response handed over is not one of
            // them, whichever response handed it over last.** This used to let
            // the most recent appearance decide, on the reasoning that history
            // arrives newest first — but a `no-store` response re-offering a
            // tag does not unmake the store an earlier response licensed.
            // § 5.2.2.5 forbids storing *that* response; nothing in it evicts
            // an entry already held, and § 4.4's invalidation is about unsafe
            // methods. So `max-age=60, ETag: "v1"` followed by `no-store,
            // ETag: "v1"` and then `If-None-Match: "v1"` is a client
            // revalidating exactly what it was allowed to keep, and it was
            // reported for holding it.
            //
            // The answer is a subtraction rather than a race: a tag is
            // evidence only if *no* response a cache could store ever offered
            // it. `storage_allowed` is what "could store" means here, so the
            // directive on the earlier request counts the same as the one on
            // the response — the same reading the rules that reconstruct an
            // entry from history apply.
            use std::collections::{HashMap, HashSet};

            // ETags compare with the weak prefix stripped; the raw text is kept
            // for the finding message.
            let mut no_store_etags: HashSet<String> = HashSet::new();
            // Last-Modified is compared both as written and as a timestamp, so
            // the parse is done once here rather than per candidate below.
            let mut no_store_lastmod: HashMap<String, chrono::DateTime<chrono::Utc>> =
                HashMap::new();
            // The validators an exchange the client was allowed to store handed
            // over. Everything in here leaves the sets above at the end.
            let mut storable_etags: HashSet<String> = HashSet::new();
            let mut storable_lastmod: HashSet<String> = HashSet::new();
            // And the instants they name, because the matching below compares
            // both spellings and instants: a licensed `...07:28:00 GMT` beside
            // a `no-store` `...07:28:00 UTC` is one time, and subtracting only
            // the string would leave the other key standing.
            let mut storable_instants: HashSet<chrono::DateTime<chrono::Utc>> = HashSet::new();

            for (prev_tx, resp) in history.responses() {
                let stored = crate::helpers::stored_response::storage_allowed(
                    &prev_tx.request.headers,
                    &resp.headers,
                );

                if let Some(etag) = crate::helpers::headers::get_header_str(&resp.headers, "etag") {
                    let normalized = crate::helpers::validator::normalize_etag(etag);
                    if stored {
                        storable_etags.insert(normalized);
                    } else {
                        no_store_etags.insert(normalized);
                    }
                }

                if let Some(lastmod) =
                    crate::helpers::headers::get_header_str(&resp.headers, "last-modified")
                {
                    let val = lastmod.trim().to_string();
                    if stored {
                        if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(&val) {
                            storable_instants.insert(dt);
                        }
                        storable_lastmod.insert(val);
                    } else if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(&val) {
                        // An unparseable date matches no candidate later, so
                        // there is nothing to record for it.
                        no_store_lastmod.insert(val, dt);
                    }
                }
            }

            // The subtraction. A validator offered by both kinds of response is
            // one the client held legitimately.
            no_store_etags.retain(|e| !storable_etags.contains(e));
            no_store_lastmod
                .retain(|v, dt| !storable_lastmod.contains(v) && !storable_instants.contains(dt));

            // helper to check If-None-Match header members against bad etags.  RFC
            // dictates that multiple header fields are concatenated with commas, and
            // HeaderMap.get_all() returns all values in order.
            for s in crate::helpers::headers::field_lines(&tx.request.headers, "if-none-match") {
                for member in crate::helpers::list::list_members(s) {
                    let normalized = crate::helpers::validator::normalize_etag(member);
                    // A validator echoed back from a no-store response is proof the client
                    // stored the thing it was told not to store.
                    // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
                    if no_store_etags.contains(&normalized) {
                        return Some(ctx.report_with(
                            &CACHE_CONTROL_NO_STORE_IGNORED,
                            format!(
                                "Conditional request uses ETag '{}' from a no-store response",
                                member
                            ),
                        ));
                    }
                }
            }

            // check If-Modified-Since; treat each header field separately since the
            // syntax is a single HTTP-date per field.  To avoid reparsing the same
            // candidate over and over we parse it once before iterating through the
            // historical values.
            for s in crate::helpers::headers::field_lines(&tx.request.headers, "if-modified-since")
            {
                let candidate = s.trim();
                let candidate_dt = crate::http_date::parse_http_date_to_datetime(candidate).ok();

                // A Last-Modified validator echoed back from a no-store response is the same
                // evidence of forbidden storage as the ETag case above.
                // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
                if no_store_lastmod.contains_key(candidate)
                    || (candidate_dt.is_some()
                        && no_store_lastmod
                            .values()
                            .any(|lm_dt| lm_dt == &candidate_dt.unwrap()))
                {
                    return Some(ctx.report_with(
                        &CACHE_CONTROL_NO_STORE_IGNORED,
                        format!(
                            "Conditional request uses Last-Modified '{}' from a no-store response",
                            candidate
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
static REGISTRATION: &dyn crate::rules::Rule = &NoStoreEnforced;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction_with_response;
    use chrono::Utc;

    /// Helper creating a previous transaction for the given resource and
    /// cache-control headers.  The response will carry the supplied headers.
    fn make_prev(
        cc_headers: &[(&str, &str)],
        validators: &[(&str, &str)],
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = make_test_transaction_with_response(200, cc_headers);
        prev.request.method = "GET".to_string();
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        prev.timestamp = ts;
        for (name, val) in validators {
            // create a header value owned by this function so we don't borrow
            // from the input slice.  HeaderValue::from_bytes copies the data.
            let hv = hyper::header::HeaderValue::from_bytes(val.as_bytes()).unwrap();
            let name_hdr: hyper::header::HeaderName = (*name).parse().unwrap();
            prev.response.as_mut().unwrap().headers.append(name_hdr, hv);
        }
        prev
    }

    #[test]
    fn no_violation_without_history() {
        let rule = NoStoreEnforced;
        let tx = crate::test_helpers::make_test_transaction();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_none());
    }

    #[test]
    fn no_violation_if_history_has_no_store_but_request_not_conditional() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_none());
    }

    #[test]
    fn violation_on_if_none_match_matching_no_store() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        );
        // The entry an operator configures, and the ending that says who is
        // at fault: the response stated the directive correctly and a cache
        // did not honour it.
        let v = v.expect("a finding");
        assert_eq!(v.violation, "cache_control_no_store_ignored");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("ETag"));
    }

    /// A validator a storable response handed over is not evidence of a
    /// forbidden store, however the same value is spelled afterwards.
    ///
    /// `max-age=60, ETag: "a"` licenses the client to keep the tag. A later
    /// `no-store` response carrying the same tag forbids storing *that*
    /// response and evicts nothing, so the conditional request that follows is
    /// the client revalidating exactly what it was allowed to keep. Reading the
    /// most recent appearance as the one that decides reported it as theft.
    #[rstest::rstest]
    // Newest first, and the order is the point: whichever way round the two
    // responses sit, one of them licensed the tag.
    #[case(&["no-store", "max-age=60"], "if-none-match", "\"a\"", false)]
    #[case(&["max-age=60", "no-store"], "if-none-match", "\"a\"", false)]
    // Only ever offered by a response nothing stored: still the finding.
    #[case(&["no-store", "no-store"], "if-none-match", "\"a\"", true)]
    #[case(&["no-store"], "if-none-match", "\"a\"", true)]
    fn a_validator_a_storable_response_offered_is_not_evidence_of_a_forbidden_store(
        #[case] cache_controls: &[&str],
        #[case] field: &str,
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = NoStoreEnforced;
        let base = Utc::now();
        let history = crate::transaction_history::TransactionHistory::from_transactions(
            cache_controls
                .iter()
                .enumerate()
                .map(|(i, cc)| {
                    make_prev(
                        &[("cache-control", cc)],
                        &[("etag", value)],
                        base - chrono::Duration::seconds(i as i64),
                    )
                })
                .collect(),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        );
        assert_eq!(v.is_some(), expect_violation, "{:?}", v.map(|v| v.message));
    }

    /// The same subtraction on the date half, and the boundary beside it.
    #[test]
    fn a_last_modified_a_storable_response_offered_is_not_evidence_either() {
        let rule = NoStoreEnforced;
        let base = Utc::now();
        let date = "Wed, 21 Oct 2015 07:28:00 GMT";
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-modified-since", date)]);

        let licensed = crate::transaction_history::TransactionHistory::from_transactions(vec![
            make_prev(
                &[("cache-control", "no-store")],
                &[("last-modified", date)],
                base,
            ),
            make_prev(
                &[("cache-control", "max-age=60")],
                &[("last-modified", date)],
                base - chrono::Duration::seconds(1),
            ),
        ]);
        assert!(crate::test_helpers::run_rule(&rule, &tx, &licensed, &cfg).is_none());

        let never_licensed =
            crate::transaction_history::TransactionHistory::from_transactions(vec![make_prev(
                &[("cache-control", "no-store")],
                &[("last-modified", date)],
                base,
            )]);
        assert!(crate::test_helpers::run_rule(&rule, &tx, &never_licensed, &cfg).is_some());
    }

    /// The directive on the earlier *request* keeps a cache from storing the
    /// response to it, so a tag only such an exchange offered is the same
    /// evidence the response-side directive is.
    #[test]
    fn a_request_that_forbade_storing_taints_the_tag_its_response_offered() {
        let rule = NoStoreEnforced;
        let mut prev = make_prev(&[], &[("etag", "\"a\"")], Utc::now());
        prev.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", "no-store")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "cache_control_no_store_ignored");
    }

    #[test]
    fn violation_on_if_none_match_weak_validator() {
        // a weak validator in history should match a strong one in request and
        // vice versa; normalization makes sure the rule doesn't miss this.
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "W/\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_some());
    }

    #[test]
    fn violation_on_if_modified_since_matching_no_store() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(
            &[("cache-control", "no-store")],
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
            ts,
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Last-Modified"));
    }

    #[test]
    fn non_matching_validator_not_flagged() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"b\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_none());
    }

    #[test]
    fn later_non_no_store_supersedes() {
        // if a validator value appears later in history attached to a
        // non-no-store response, it should no longer be considered
        // prohibited even if an earlier entry had it with no-store.
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev1 = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let prev2 = make_prev(
            &[("cache-control", "max-age=60")],
            &[("etag", "\"a\"")],
            ts + chrono::Duration::seconds(1),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev2, prev1]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_none());
    }

    #[test]
    fn later_non_no_store_supersedes_last_modified() {
        // same as above but for Last-Modified
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let lm = "Wed, 21 Oct 2015 07:28:00 GMT";
        let prev1 = make_prev(
            &[("cache-control", "no-store")],
            &[("last-modified", lm)],
            ts,
        );
        let prev2 = make_prev(
            &[("cache-control", "max-age=60")],
            &[("last-modified", lm)],
            ts + chrono::Duration::seconds(1),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-modified-since", lm)]);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev2, prev1]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_none());
    }

    #[test]
    fn multiple_if_none_match_values() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        // multiple values, one matching
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"x\", \"a\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_some());
    }

    #[test]
    fn multiple_header_fields_for_if_none_match() {
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        let mut hm = hyper::HeaderMap::new();
        hm.append("if-none-match", "\"x\"".parse().unwrap());
        hm.append("if-none-match", "\"a\"".parse().unwrap());
        tx.request.headers = hm;
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_some());
    }

    #[test]
    fn last_modified_date_string_inequality() {
        // If dates parse to same instant but differ in formatting we still want a violation.
        let rule = NoStoreEnforced;
        let ts = Utc::now();
        let prev = make_prev(
            &[("cache-control", "no-store")],
            &[("last-modified", "Sun, 06 Nov 1994 08:49:37 GMT")],
            ts,
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        // same instant produced by http_date parser but perhaps different text (same here)
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Sun, 06 Nov 1994 08:49:37 GMT",
        )]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["no_store_enforced"]),
        )
        .is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "no_store_enforced");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
