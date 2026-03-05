// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that the freshness lifetime advertised by
/// `Cache-Control: max-age=<seconds>` is actually respected by a client or
/// cache when re-requesting a resource.
///
/// The rule looks back at the most recent previous response for the same
/// client+resource that carried a valid `max-age` directive.  It computes an
/// approximate current "age" for that response based on the captured
/// timestamp, any `Age` header, and the elapsed time since the response was
/// seen.  Two kinds of misbehaviour are flagged:
///
/// * A conditional request (`If-None-Match`/`If-Modified-Since`) is issued
///   while the stored response is still within its freshness lifetime.  Our
///   view of the same resource should have been fresh and therefore there is
///   no need to revalidate yet.
/// * An unconditional request is issued **after** the freshness lifetime has
///   expired *and* the previous response carried at least one validator
///   (ETag/Last-Modified).  In that case the client/cache should have
///   revalidated rather than blindly reuse a stale entry.
///
/// This stateful check complements the stateless `client_cache_respect` rule
/// (which merely ensures that conditional headers are included when validators
/// exist) by tying the presence of those headers to the actual freshness
/// lifetime of a cached response.
pub struct StatefulMaxAgeDirectiveValidity;

impl Rule for StatefulMaxAgeDirectiveValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_max_age_directive_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // examines both request and past responses
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // locate most recent prior response with a usable max-age
        let mut candidate: Option<(&crate::http_transaction::HttpTransaction, i64)> = None;

        for past in history.iter() {
            if let Some(resp) = &past.response {
                // collect max-age value (ignore bad syntax)
                if let Some(max_age) =
                    crate::helpers::headers::get_cache_control_max_age(&resp.headers)
                {
                    candidate = Some((past, max_age));
                    break;
                }
            }
        }

        let (prev_tx, max_age) = candidate?;

        // calculate current age: Age header (if numeric) + elapsed seconds
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

        if current_age < max_age {
            if has_conditional {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Request revalidated resource while response is still fresh (age {} < max-age {})",
                        current_age, max_age
                    ),
                });
            }
        } else if !has_conditional {
            // only warn if there was something to validate against
            let resp = prev_tx.response.as_ref().unwrap();
            let has_validator =
                resp.headers.contains_key("etag") || resp.headers.contains_key("last-modified");
            if has_validator {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Stale cached entry (age {} >= max-age {}) reused without conditional request; should revalidate",
                        current_age, max_age
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
    use crate::test_helpers::{make_test_rule_config, make_test_transaction_with_response};
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

    #[test]
    fn fresh_unconditional_no_violation() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(30);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn boundary_age_equal_unconditional_reports() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        // age == max-age should count as stale
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=10"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev.clone()]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(
            v.is_some(),
            "unconditional fetch at exact boundary should warn"
        );

        // conditional at boundary should be permitted
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = crate::test_helpers::make_test_client();
        tx2.request.uri = "/resource".to_string();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx2.timestamp = base + chrono::Duration::seconds(10);
        let history2 = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(
            rule.check_transaction(&tx2, &history2, &make_test_rule_config())
                .is_none(),
            "conditional at boundary should not warn"
        );
    }

    #[test]
    fn fresh_conditional_reports_violation() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=60"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("still fresh"));
    }

    #[test]
    fn stale_conditional_is_ok() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=1"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn stale_unconditional_reports_when_validator_present() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=1"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Stale cached entry"));
    }

    #[test]
    fn stale_unconditional_no_violation_without_validator() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "max-age=1")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(5);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn no_max_age_skips() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "no-store")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn max_age_ignored_when_no_cache_or_no_store() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        // previous response had max-age but also no-cache, should be ignored
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, no-cache")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(
            v.is_none(),
            "max-age should be ignored when no-cache present"
        );
    }

    #[test]
    fn age_header_affects_freshness() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        // age header 10 + elapsed 30 = 40 < max-age 100
        let prev = make_prev_with_headers(&[("cache-control", "max-age=100"), ("age", "10")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(30);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some(), "expected violation because still fresh");
    }

    #[test]
    fn age_header_makes_stale_unconditional() {
        let rule = StatefulMaxAgeDirectiveValidity;
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

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(
            v.is_some(),
            "should flag stale unconditional with age header"
        );
    }

    #[test]
    fn max_age_zero_behaviour() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        // zero max-age means freshness lifetime is immediate
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=0"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base;
        let history = crate::transaction_history::TransactionHistory::new(vec![prev.clone()]);
        // age == max-age should be treated as stale; unconditional request
        // should therefore be flagged since validator exists.
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_some(), "unconditional fetch at boundary should warn");

        // conditional at same moment is appropriate (entry stale) and should NOT trigger a violation
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = crate::test_helpers::make_test_client();
        tx2.request.uri = "/resource".to_string();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx2.timestamp = base;
        let history2 = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(
            rule.check_transaction(&tx2, &history2, &make_test_rule_config())
                .is_none(),
            "conditional at boundary should not warn"
        );
    }

    #[test]
    fn negative_elapsed_is_clamped() {
        let rule = StatefulMaxAgeDirectiveValidity;
        let base = Utc::now();

        // transaction timestamp earlier than prev
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=5"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base - chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        // age computed from elapsed clamped to 0 yields fresh state; no violation expected
        let v = rule.check_transaction(&tx, &history, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn cache_control_max_age_helper_tests() {
        use crate::helpers::headers::get_cache_control_max_age;

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
        crate::test_helpers::enable_rule(&mut cfg, "stateful_max_age_directive_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
