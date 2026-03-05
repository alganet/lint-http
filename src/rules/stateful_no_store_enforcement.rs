// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that responses marked `no-store` are never reused for later
/// conditional requests.  The `no-store` directive (RFC 9111 §5.2.2.3) tells
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
pub struct StatefulNoStoreEnforcement;

impl Rule for StatefulNoStoreEnforcement {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_no_store_enforcement"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // examine both requests and previous responses for the resource
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Build maps of validators to a boolean indicating whether the most
        // recent occurrence of that validator came from a no-store response.
        //
        // The `TransactionHistory` type is documented to yield entries "newest
        // first" (see its own docs).  Our algorithm depends on that ordering
        // so that the first time we see a given validator value we record the
        // state that should win.  To make the assumption explicit and guard
        // against future changes in history construction we sort the entries
        // ourselves by timestamp.  That way the rule behaves correctly even if
        // the caller accidentally supplies an unsorted vector.
        use std::collections::HashSet;

        // We'll keep normalized ETag values (weak prefix stripped) for
        // comparison, but retain the original header text in violation
        // messages.  `seen_etags` tracks normalized values we've already
        // encountered so that later entries win.
        let mut no_store_etags: HashSet<String> = HashSet::new();
        let mut seen_etags: HashSet<String> = HashSet::new();

        // For Last-Modified we need both the raw string (for direct
        // comparisons) and a parsed `DateTime` to avoid reparsing the same
        // history value on every request.  Store the parsed time in the map
        // keyed by the raw string so we can easily remove entries when a
        // later non-no-store response overrides them.
        let mut no_store_lastmod: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>> =
            std::collections::HashMap::new();
        let mut seen_lastmod: HashSet<String> = HashSet::new();

        // Collect the entries and ensure newest-first ordering by timestamp.
        // This is a small extra cost, but the history is typically short.
        let mut entries: Vec<&crate::http_transaction::HttpTransaction> = history.iter().collect();
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // debug-time sanity check: timestamps should now be non-increasing.
        #[cfg(debug_assertions)]
        {
            for pair in entries.windows(2) {
                if let [first, second] = pair {
                    debug_assert!(
                        first.timestamp >= second.timestamp,
                        "history entries must be newest-first"
                    );
                }
            }
        }

        for past in entries {
            if let Some(resp) = &past.response {
                let is_no_store = header_has_no_store(&resp.headers);

                if let Some(hv) = resp.headers.get("etag") {
                    if let Ok(s) = hv.to_str() {
                        let val = s.trim().to_string();
                        let normalized = normalize_etag(&val);
                        if !seen_etags.contains(&normalized) {
                            seen_etags.insert(normalized.clone());
                            if is_no_store {
                                no_store_etags.insert(normalized.clone());
                            } else {
                                no_store_etags.remove(&normalized);
                            }
                        }
                    }
                }

                if let Some(hv) = resp.headers.get("last-modified") {
                    if let Ok(s) = hv.to_str() {
                        let val = s.trim().to_string();
                        if !seen_lastmod.contains(&val) {
                            seen_lastmod.insert(val.clone());
                            if is_no_store {
                                // parse once and store if successful
                                if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(&val)
                                {
                                    no_store_lastmod.insert(val.clone(), dt);
                                } else {
                                    // unparsable dates can't match later, so
                                    // ensure they're not in the map
                                    no_store_lastmod.remove(&val);
                                }
                            } else {
                                no_store_lastmod.remove(&val);
                            }
                        }
                    }
                }
            }
        }

        // helper to check If-None-Match header members against bad etags.  RFC
        // dictates that multiple header fields are concatenated with commas, and
        // HeaderMap.get_all() returns all values in order.
        for hv in tx.request.headers.get_all("if-none-match").iter() {
            if let Ok(s) = hv.to_str() {
                for member in crate::helpers::headers::parse_list_header(s) {
                    let member = member.trim();
                    let normalized = normalize_etag(member);
                    if no_store_etags.contains(&normalized) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Conditional request uses ETag '{}' from a no-store response",
                                member
                            ),
                        });
                    }
                }
            }
        }

        // check If-Modified-Since; treat each header field separately since the
        // syntax is a single HTTP-date per field.  To avoid reparsing the same
        // candidate over and over we parse it once before iterating through the
        // historical values.
        for hv in tx.request.headers.get_all("if-modified-since").iter() {
            if let Ok(s) = hv.to_str() {
                let candidate = s.trim();
                let candidate_dt = crate::http_date::parse_http_date_to_datetime(candidate).ok();

                if no_store_lastmod.contains_key(candidate)
                    || (candidate_dt.is_some()
                        && no_store_lastmod
                            .values()
                            .any(|lm_dt| lm_dt == &candidate_dt.unwrap()))
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Conditional request uses Last-Modified '{}' from a no-store response",
                            candidate
                        ),
                    });
                }
            }
        }

        None
    }
}

/// Look for a `no-store` directive in any Cache-Control header field.
fn header_has_no_store(headers: &hyper::HeaderMap) -> bool {
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            for directive in s.split(|c| [',', ';'].contains(&c)) {
                if directive.trim().eq_ignore_ascii_case("no-store") {
                    return true;
                }
            }
        }
    }
    false
}

/// Strip an optional weak (`W/`) prefix from an ETag value, leaving the
/// quoted-string intact.  Comparison logic throughout the rule operates on
/// normalized values so that weak and strong validators match each other as
/// required by RFC 9111 §5.3.2.
fn normalize_etag(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() >= 2 && (trimmed.starts_with("W/") || trimmed.starts_with("w/")) {
        trimmed[2..].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_rule_config, make_test_transaction_with_response};
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
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn no_violation_if_history_has_no_store_but_request_not_conditional() {
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn violation_on_if_none_match_matching_no_store() {
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("ETag"));
    }

    #[test]
    fn violation_on_if_none_match_weak_validator() {
        // a weak validator in history should match a strong one in request and
        // vice versa; normalization makes sure the rule doesn't miss this.
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "W/\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn violation_on_if_modified_since_matching_no_store() {
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Last-Modified"));
    }

    #[test]
    fn non_matching_validator_not_flagged() {
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"b\"")]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn later_non_no_store_supersedes() {
        // if a validator value appears later in history attached to a
        // non-no-store response, it should no longer be considered
        // prohibited even if an earlier entry had it with no-store.
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
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
            crate::transaction_history::TransactionHistory::new(vec![prev2.clone(), prev1.clone()]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn later_non_no_store_supersedes_last_modified() {
        // same as above but for Last-Modified
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
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
            crate::transaction_history::TransactionHistory::new(vec![prev2.clone(), prev1.clone()]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
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
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        // multiple values, one matching
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"x\", \"a\"")]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn multiple_header_fields_for_if_none_match() {
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let prev = make_prev(&[("cache-control", "no-store")], &[("etag", "\"a\"")], ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        let mut hm = hyper::HeaderMap::new();
        hm.append("if-none-match", "\"x\"".parse().unwrap());
        hm.append("if-none-match", "\"a\"".parse().unwrap());
        tx.request.headers = hm;
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn last_modified_date_string_inequality() {
        // If dates parse to same instant but differ in formatting we still want a violation.
        let rule = StatefulNoStoreEnforcement;
        let cfg = make_test_rule_config();
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_no_store_enforcement");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }
}
