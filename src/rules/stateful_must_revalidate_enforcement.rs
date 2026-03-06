// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

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
/// most recent response that contained a `must-revalidate` directive.  It then
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
pub struct StatefulMustRevalidateEnforcement;

impl Rule for StatefulMustRevalidateEnforcement {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_must_revalidate_enforcement"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // we need to inspect both the request and prior responses
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // find the most recent past response that contained must-revalidate
        let mut candidate: Option<&crate::http_transaction::HttpTransaction> = None;
        for past in history.iter() {
            if let Some(resp) = &past.response {
                if header_has_must_revalidate(&resp.headers) {
                    candidate = Some(past);
                    break;
                }
            }
        }

        let prev_tx = candidate?;

        // compute freshness lifetime advertised by the response.  this uses a
        // shared helper which handles both `max-age` and `Expires` logic,
        // returning zero when no explicit lifetime is available.
        let freshness_lifetime = crate::helpers::headers::compute_freshness_lifetime(
            &prev_tx.response.as_ref().unwrap().headers,
            prev_tx.timestamp,
        );

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

        // treat equal age as stale as well; a freshness lifetime of zero is
        // therefore immediately expired.
        if current_age >= freshness_lifetime && !has_conditional {
            // warn only if there was a validator on the original response
            let resp = prev_tx.response.as_ref().unwrap();
            let has_validator =
                resp.headers.contains_key("etag") || resp.headers.contains_key("last-modified");
            if has_validator {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Cached response with 'must-revalidate' directive is stale (age {} >= freshness {}) and was reused without conditional request",
                        current_age, freshness_lifetime
                    ),
                });
            }
        }

        None
    }
}

/// Helper to detect presence of a must-revalidate directive in Cache-Control
/// headers.  We perform a case-insensitive substring check on semicolon- and
/// comma-separated directives so that the header grammar complexity does not
/// need to be duplicated here.
fn header_has_must_revalidate(headers: &hyper::HeaderMap) -> bool {
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            // Cache-Control is a comma-separated list of directives; some
            // implementations also use semicolons.  Accept either separator.
            for directive in s.split(|c| [',', ';'].contains(&c)) {
                if directive.trim().eq_ignore_ascii_case("must-revalidate") {
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
        let rule = StatefulMustRevalidateEnforcement;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unrelated_history_ignored() {
        let rule = StatefulMustRevalidateEnforcement;
        let prev = make_prev(200, &[("cache-control", "max-age=60")]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let tx = crate::test_helpers::make_test_transaction();
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
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
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        // current_age should equal age header (5) not negative elapsed
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        // freshness zero and no validator -> no violation
        assert!(v.is_none());
    }

    #[test]
    fn age_header_contributes_to_violation() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev.clone()]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_age_header_treated_as_age_zero() {
        // with the >= comparison an unparseable Age header (treated as zero)
        // combined with a zero freshness lifetime should now be considered
        // stale when a validator is present.
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some(), "equal age should now be treated as stale");
    }

    #[test]
    fn must_revalidate_with_validator_no_conditional_reports() {
        let rule = StatefulMustRevalidateEnforcement;
        let base = chrono::Utc::now();
        let mut prev = make_prev(
            200,
            &[("cache-control", "must-revalidate"), ("etag", "\"v\"")],
        );
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn must_revalidate_without_validator_no_violation() {
        let rule = StatefulMustRevalidateEnforcement;
        let base = chrono::Utc::now();
        // previous response has must-revalidate but no validator at all
        let mut prev = make_prev(200, &[("cache-control", "must-revalidate")]);
        prev.timestamp = base;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(5);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn fresh_entity_with_max_age_ok() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn stale_entity_with_max_age_warns() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn stale_entity_revalidated_is_ok() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn stale_entity_age_equal_warns() {
        // equality should count as stale under the new >= logic
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some(), "equal age should be considered stale");
    }

    #[test]
    fn zero_max_age_with_validator_immediately_stale() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some(), "max-age=0 should be stale immediately");
    }

    #[test]
    fn conditional_before_stale_ok() {
        let rule = StatefulMustRevalidateEnforcement;
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
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v =
            rule.check_transaction(&tx, &history, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_must_revalidate_enforcement");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_must_revalidate_enforcement");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("stateful_must_revalidate_enforcement")
        {
            table.remove("severity");
        }
        assert!(crate::rules::validate_rules(&cfg).is_err());
    }
}
