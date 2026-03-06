// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that responses labelled `Cache-Control: immutable` are not
/// needlessly revalidated while still within their advertised freshness
/// lifetime.  The `immutable` directive (RFC 8246) tells caches that the
/// representation will not change; clients SHOULD therefore treat the
/// entry as fresh for the duration of its freshness lifetime and avoid
/// conditional requests during that period.  Sending a conditional request
/// (e.g. `If-None-Match`/`If-Modified-Since`) while the cached entry is still
/// fresh is wasteful and indicates the client is not honouring the
/// directive.
///
/// The rule scans the transaction history for the most recent prior response
/// containing an `immutable` directive without accompanying `no-store` or
/// `no-cache` (these directives forbid caching).  If such a response is found,
/// the helper in `helpers::headers` is used to compute its advertised freshness
/// lifetime; the current "age" of the entry is estimated using the `Age`
/// header and elapsed time since the response was observed.  If the
/// current request for that resource includes a conditional header and the
/// entry would still be fresh at that moment (age < freshness lifetime), a
/// warning is emitted.  No violation is raised for unconditional requests or
/// for any requests made after the freshness lifetime has expired; once the
/// entry is stale, normal caching rules apply and this rule no longer emits,
/// regardless of whether the request is conditional or unconditional.
pub struct StatefulImmutableCacheNeverStale;

impl Rule for StatefulImmutableCacheNeverStale {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_immutable_cache_never_stale"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // locate the most recent prior response with an immutable
        // directive that isn't simultaneously forbidding caching.
        let mut candidate: Option<&crate::http_transaction::HttpTransaction> = None;
        for past in history.iter() {
            if let Some(resp) = &past.response {
                if header_has_immutable(&resp.headers) {
                    candidate = Some(past);
                    break;
                }
            }
        }

        let prev_tx = candidate?;

        // compute advertised freshness lifetime (helper handles max-age/Expires)
        let freshness_lifetime = crate::helpers::headers::compute_freshness_lifetime(
            &prev_tx.response.as_ref().unwrap().headers,
            prev_tx.timestamp,
        );

        // compute current age
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
        let current_age = age_val.saturating_add(elapsed);

        let has_conditional = tx.request.headers.contains_key("if-none-match")
            || tx.request.headers.contains_key("if-modified-since");

        if has_conditional && current_age < freshness_lifetime {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Unnecessary revalidation of immutable response while still fresh (age {} < freshness {})",
                    current_age, freshness_lifetime
                ),
            });
        }

        None
    }
}

/// Detect the presence of `immutable` in Cache-Control headers.  We ignore
/// values that also forbid caching (`no-store` or `no-cache`).
fn header_has_immutable(headers: &hyper::HeaderMap) -> bool {
    // if any field forbids caching, treat the whole response as non-cacheable
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            let l = s.to_ascii_lowercase();
            if l.contains("no-store") || l.contains("no-cache") {
                return false;
            }
        }
    }
    // now search for immutable directive across fields
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            for directive in s.split(|c| [',', ';'].contains(&c)) {
                if directive.trim().eq_ignore_ascii_case("immutable") {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_rule_config, make_test_transaction_with_response};
    use chrono::Utc;
    use hyper::header::HeaderValue;

    #[test]
    fn header_has_immutable_variations() {
        let mut hm = hyper::HeaderMap::new();
        // no header
        assert!(!header_has_immutable(&hm));
        // simple immutable
        hm.insert("cache-control", "immutable".parse().unwrap());
        assert!(header_has_immutable(&hm));
        // case insensitivity
        hm.clear();
        hm.insert("cache-control", "ImMuTaBlE".parse().unwrap());
        assert!(header_has_immutable(&hm));
        // comma separated
        hm.clear();
        hm.insert("cache-control", "max-age=0, immutable".parse().unwrap());
        assert!(header_has_immutable(&hm));
        // semicolon separated
        hm.clear();
        hm.insert("cache-control", "immutable; max-age=0".parse().unwrap());
        assert!(header_has_immutable(&hm));
        // ignore when no-cache or no-store present in same header
        hm.clear();
        hm.insert("cache-control", "immutable, no-cache".parse().unwrap());
        assert!(!header_has_immutable(&hm));
        hm.clear();
        hm.insert("cache-control", "no-store, immutable".parse().unwrap());
        assert!(!header_has_immutable(&hm));
        // ignore when directives split across headers
        hm.clear();
        hm.append("cache-control", "immutable".parse().unwrap());
        hm.append("cache-control", "no-cache".parse().unwrap());
        assert!(!header_has_immutable(&hm));
        hm.clear();
        hm.append("cache-control", "no-store".parse().unwrap());
        hm.append("cache-control", "immutable".parse().unwrap());
        assert!(!header_has_immutable(&hm));
    }

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

    #[test]
    fn no_history_no_violation() {
        let rule = StatefulImmutableCacheNeverStale;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unrelated_history_ignored() {
        let rule = StatefulImmutableCacheNeverStale;
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], Utc::now());
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn fresh_conditional_reports_violation() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unnecessary revalidation"));
    }

    #[test]
    fn boundary_age_conditional_allowed() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=10, immutable"),
                ("etag", "\"a\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule
            .check_transaction(&tx, &history, &make_test_rule_config())
            .is_none());
    }

    #[test]
    fn stale_conditional_ok() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=1, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule
            .check_transaction(&tx, &history, &make_test_rule_config())
            .is_none());
    }

    #[test]
    fn no_immutable_skips() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule
            .check_transaction(&tx, &history, &make_test_rule_config())
            .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_immutable_cache_never_stale");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }

    #[test]
    fn unconditional_fresh_no_violation() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        // previous immutable response fresh for 60s
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none(), "unconditional fresh use should not warn");
    }

    #[test]
    fn conditional_with_age_and_negative_elapsed() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let mut prev = make_prev_with_headers(&[("cache-control", "max-age=50, immutable")], base);
        // add age header
        prev.response
            .as_mut()
            .unwrap()
            .headers
            .append("age", HeaderValue::from_static("5"));
        // make request timestamp earlier than prev to trigger negative elapsed
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        tx.timestamp = base - chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        // age_val=5, elapsed clamped to 0 -> current_age=5 < freshness(50) => violation
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn conditional_no_freshness_skips() {
        let rule = StatefulImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        // freshness lifetime zero, so no violation should be reported
        assert!(rule
            .check_transaction(&tx, &history, &make_test_rule_config())
            .is_none());
    }
}
