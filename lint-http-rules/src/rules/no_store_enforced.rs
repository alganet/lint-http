// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

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
const RFC_9111_5_2_2_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5",
    note: "`no-store`",
};
const RFC_9111_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3",
    note: "Validation (conditional requests carry the validators this rule tracks)",
};

impl Rule for NoStoreEnforced {
    fn id(&self) -> &'static str {
        "no_store_enforced"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // examine both requests and previous responses for the resource
        crate::rules::RuleScope::Both
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
            // Which validators came from a no-store response, and which did not.
            //
            // The history yields entries newest first — the container asserts
            // that invariant where it is built — so the *first* appearance of a
            // validator is its most recent one, and that is the appearance that
            // decides. The `seen` sets below are what make later (older)
            // entries unable to overwrite it; the earlier reading of this rule
            // also removed from the no-store sets on a non-no-store entry, which
            // could never fire — nothing is inserted for a validator that was
            // already seen — and said the same decision twice.
            use std::collections::{HashMap, HashSet};

            // ETags compare with the weak prefix stripped; the raw text is kept
            // for the finding message.
            let mut no_store_etags: HashSet<String> = HashSet::new();
            // Last-Modified is compared both as written and as a timestamp, so
            // the parse is done once here rather than per candidate below.
            let mut no_store_lastmod: HashMap<String, chrono::DateTime<chrono::Utc>> =
                HashMap::new();
            let mut seen_etags: HashSet<String> = HashSet::new();
            let mut seen_lastmod: HashSet<String> = HashSet::new();

            for (_, resp) in history.responses() {
                let is_no_store = header_has_no_store(&resp.headers);

                if let Some(etag) = crate::helpers::headers::get_header_str(&resp.headers, "etag") {
                    let normalized = crate::helpers::validator::normalize_etag(etag);
                    if seen_etags.insert(normalized.clone()) && is_no_store {
                        no_store_etags.insert(normalized);
                    }
                }

                if let Some(lastmod) =
                    crate::helpers::headers::get_header_str(&resp.headers, "last-modified")
                {
                    let val = lastmod.trim().to_string();
                    // An unparseable date matches no candidate later, so it is
                    // recorded as seen and nothing more.
                    if seen_lastmod.insert(val.clone()) && is_no_store {
                        if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(&val) {
                            no_store_lastmod.insert(val, dt);
                        }
                    }
                }
            }

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
                        return Some(self.cited(
                            &RFC_9111_5_2_2_5,
                            ctx.severity,
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
                    return Some(self.cited(
                        &RFC_9111_5_2_2_5,
                        ctx.severity,
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

    fn title(&self) -> Option<&'static str> {
        Some("Stateful no-store enforcement")
    }

    fn description(&self) -> &'static str {
        "The `no-store` cache-control directive (RFC 9111 §5.2.2.5) tells caches that **they must not retain any part of the response or request**.  A cache that breaks this rule may later reuse stale or private data inappropriately.\n\nThis stateful rule observes the history of a particular client+resource and remembers which validator values (ETag or Last-Modified) were seen on responses that carried `Cache-Control: no-store`.  Only the most recent occurrence of each validator is kept; if the same value later appears on a non‑`no-store` response it is no longer considered forbidden.  When the current request carries a conditional header whose value matches one of those \"no-store\" validators, we infer that the response must have been stored at some point, and a violation is reported.\n\nThe check is scoped to resource histories (the engine filters transactions by URI) and therefore does not attempt to reason about unrelated traffic.  The rule does not flag unconditional requests, nor does it attempt to detect improper storage of requests (which is rarely visible from traffic capture)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2_2_5, RFC_9111_4_3]
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

/// Look for a `no-store` directive in any Cache-Control header field.
///
/// `no-store` is defined with no argument, so the bare form is the only form,
/// and asking for it excludes a member that merely starts with the name.
fn header_has_no_store(headers: &hyper::HeaderMap) -> bool {
    crate::helpers::cache_control::has_unqualified(headers, "no-store")
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("ETag"));
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
    fn header_has_no_store_variations() {
        let mut hm = hyper::HeaderMap::new();
        assert!(!header_has_no_store(&hm));
        hm.append("cache-control", "max-age=60".parse().unwrap());
        assert!(!header_has_no_store(&hm));
        hm.append("cache-control", "no-store".parse().unwrap());
        assert!(header_has_no_store(&hm));
        hm = hyper::HeaderMap::new();
        hm.append("cache-control", "MAX-AGE=0, No-StOrE".parse().unwrap());
        assert!(header_has_no_store(&hm));
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
