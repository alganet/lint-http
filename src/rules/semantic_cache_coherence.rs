// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that responses for a given resource do not regress in their
/// representation date.  Cache coherence (RFC 9111 §6) demands that once a
/// newer representation has been made available, caches and origin servers
/// should not subsequently serve an older copy without
/// revalidation/invalidation.  This rule approximates that requirement by
/// computing a simple timestamp for each response using the `Last-Modified`
/// header if present, or else the `Date` header, and complaining if the
/// current transaction's timestamp is strictly older than any previously
/// observed value for the same URI.  It currently does not examine validators
/// such as `ETag`.
pub struct SemanticCacheCoherence;

impl Rule for SemanticCacheCoherence {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_cache_coherence"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // the rule only inspects server responses; request headers are used
        // to identify the resource but nothing else is required.
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // ignore 304 responses, they have no representation body of their own
        if resp.status == 304 {
            return None;
        }

        // helper to extract a "representation time" from headers.  We prefer
        // Last-Modified but fall back to Date.  Return None if neither can be
        // parsed.
        fn rep_time(headers: &hyper::HeaderMap) -> Option<chrono::DateTime<chrono::Utc>> {
            if let Some(hv) = headers.get("last-modified") {
                if let Ok(s) = hv.to_str() {
                    if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                        return Some(dt);
                    }
                }
            }
            if let Some(hv) = headers.get("date") {
                if let Ok(s) = hv.to_str() {
                    if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                        return Some(dt);
                    }
                }
            }
            None
        }

        let curr_time = rep_time(&resp.headers)?; // nothing we can compare

        // scan previous history entries for the same URI and track the largest
        // timestamp we've seen so far.
        let mut max_prev: Option<chrono::DateTime<chrono::Utc>> = None;
        for prev in history.iter() {
            if prev.request.uri != tx.request.uri {
                continue;
            }
            if let Some(prev_resp) = &prev.response {
                if let Some(t) = rep_time(&prev_resp.headers) {
                    max_prev = Some(match max_prev {
                        Some(existing) => std::cmp::max(existing, t),
                        None => t,
                    });
                }
            }
        }

        if let Some(prev_max) = max_prev {
            if curr_time < prev_max {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "response for '{}' appears stale ({} < previous {})",
                        tx.request.uri, curr_time, prev_max
                    ),
                });
            }
        }

        None
    }
}

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

    #[test]
    fn no_violation_without_history() {
        let rule = SemanticCacheCoherence;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp_tx(
            "https://example.com/foo",
            200,
            &[("date", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn increasing_date_ok() {
        let rule = SemanticCacheCoherence;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&curr, &history, &cfg).is_none());
    }

    #[test]
    fn out_of_order_date_flagged() {
        let rule = SemanticCacheCoherence;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&curr, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("appears stale"));
    }

    #[test]
    fn last_modified_decrease_flagged() {
        let rule = SemanticCacheCoherence;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&curr, &history, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn no_time_headers_no_violation() {
        let rule = SemanticCacheCoherence;
        let cfg = crate::test_helpers::make_test_rule_config();
        let prev = make_resp_tx("https://example.com/foo", 200, &[]);
        let mut curr = make_resp_tx("https://example.com/foo", 200, &[]);
        curr.timestamp = prev.timestamp + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&curr, &history, &cfg).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_cache_coherence");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
