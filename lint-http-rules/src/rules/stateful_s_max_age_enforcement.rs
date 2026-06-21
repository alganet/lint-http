// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that `Cache-Control: s-maxage` is not treated as the freshness
/// lifetime by *private* clients or caches.
///
/// The `s-maxage` directive (RFC 9111 §5.2) only applies to shared caches and
/// overrides any `max-age`/`Expires` value in that context.  Private caches
/// should ignore `s-maxage` and rely on the regular freshness lifetime
/// (`max-age`/`Expires`) instead.  A private client that revalidates a resource
/// after the `s-maxage` interval but before the `max-age` interval is misusing
/// the directive and may generate unnecessary conditional requests.
///
/// This stateful rule inspects the most recent previous response for the same
/// client+resource that carried *both* an `s-maxage` and a larger `max-age`.
/// When the current request is conditional and the estimated age of the stored
/// response is **greater than or equal to** the `s-maxage` but still strictly
/// less than the `max-age`, a violation is emitted.  In other words, the
/// client revalidated based on `s-maxage` even though it should have treated
/// the entry as fresh until `max-age` expired.
pub struct StatefulSMaxAgeEnforcement;

impl Rule for StatefulSMaxAgeEnforcement {
    fn id(&self) -> &'static str {
        "stateful_s_max_age_enforcement"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // we inspect past responses as well as the current request
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // locate the most recent prior response with both s-maxage and a
        // larger max-age value.  s-maxage by itself is not actionable for this
        // check; we need a "real" private freshness lifetime to compare.
        let mut candidate: Option<(&crate::http_transaction::HttpTransaction, i64, i64)> = None;

        for past in history.iter() {
            if let Some(resp) = &past.response {
                if let Some(s_age) =
                    crate::helpers::headers::get_cache_control_s_maxage(&resp.headers)
                {
                    if let Some(max_age) =
                        crate::helpers::headers::get_cache_control_max_age(&resp.headers)
                    {
                        if max_age > s_age {
                            candidate = Some((past, s_age, max_age));
                            break;
                        }
                    }
                }
            }
        }

        let (prev_tx, s_max_age, max_age) = candidate?;

        // compute current age similar to other stateful cache rules
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

        // private cache has misapplied s-maxage if it revalidated once the age
        // crossed the s-maxage boundary but before the max-age expired.
        if has_conditional && current_age >= s_max_age && current_age < max_age {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Resource revalidated after s-maxage={} but before max-age={} (age {}) — private caches must ignore s-maxage and use max-age for freshness",
                    s_max_age, max_age, current_age
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful s-maxage Enforcement")
    }

    fn description(&self) -> &'static str {
        "Responses that include a `Cache-Control: s-maxage=<seconds>` directive are intended to limit how long **shared** caches may consider the representation fresh.  Private caches (e.g. in a browser or single-client proxy) **must ignore** `s-maxage` and instead rely on the ordinary freshness lifetime (`max-age`, `Expires`, heuristics, etc.).  Misinterpreting `s-maxage` on the client side can lead to unnecessary conditional requests and wasted network traffic.\n\nThis rule watches a series of transactions from the same client and examines the most recent prior response for the same resource that carried both an `<s-maxage>` value and a larger `max-age`.  If the client subsequently issues a conditional request **after** the `s-maxage` interval but **before** the `max-age` interval has elapsed, the cached entry was still fresh according to the private-cache semantics and revalidation was premature.  A warning is issued in that case."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9111 §5.2 — `s-maxage` directive](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2) — applies only to shared caches and overrides `max-age`/`Expires` for those caches.",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— premature revalidation based on `s-maxage`"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=3600, s-maxage=60\n< ETag: \"v1\"\n\n# seconds later, same client revalidates after 120s (s-maxage expired but\n# max-age still valid)\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulSMaxAgeEnforcement;

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

    #[test]
    fn no_history_no_violation() {
        let rule = StatefulSMaxAgeEnforcement;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_s_max_age_enforcement",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn s_maxage_without_max_age_skips() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        let prev = make_prev_with_headers(&[("cache-control", "s-maxage=5")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());
    }

    #[test]
    fn max_age_less_or_equal_s_maxage_skips() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        // equal values should not trigger
        let prev = make_prev_with_headers(&[("cache-control", "max-age=5, s-maxage=5")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(6);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());

        // max-age smaller than s-maxage also irrelevant
        let prev2 = make_prev_with_headers(&[("cache-control", "max-age=3, s-maxage=10")], base);
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.client = crate::test_helpers::make_test_client();
        tx2.request.uri = "/resource".to_string();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx2.timestamp = base + chrono::Duration::seconds(4);
        let history2 =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev2]);
        assert!(rule
            .check_transaction(
                &tx2,
                &history2,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());
    }

    #[test]
    fn conditional_between_s_and_max_age_reports_violation() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        // max-age 100, s-maxage 10; revalidate at age 20
        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=100, s-maxage=10"),
                ("etag", "\"e\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"e\"")]);
        tx.timestamp = base + chrono::Duration::seconds(20);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_s_max_age_enforcement",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("s-maxage=10"));
    }

    #[test]
    fn conditional_at_exact_s_maxage_reports() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=60, s-maxage=10"),
                ("etag", "\"e\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"e\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_some());
    }

    #[test]
    fn conditional_after_max_age_ok() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=30, s-maxage=10"),
                ("etag", "\"e\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"e\"")]);
        tx.timestamp = base + chrono::Duration::seconds(40);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());
    }

    #[test]
    fn uncond_between_s_and_max_age_no_flag() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=100, s-maxage=10"),
                ("etag", "\"e\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(20);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());
    }

    #[test]
    fn age_header_affects_violation() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        // age 15 + elapsed 5 = 20 >= s-maxage(10) and < max-age(100)
        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=100, s-maxage=10"),
                ("etag", "\"e\""),
                ("age", "15"),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"e\"")]);
        tx.timestamp = base + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_some());
    }

    #[test]
    fn negative_elapsed_is_clamped() {
        let rule = StatefulSMaxAgeEnforcement;
        let base = Utc::now();

        let prev = make_prev_with_headers(
            &[
                ("cache-control", "max-age=10, s-maxage=5"),
                ("etag", "\"e\""),
            ],
            base,
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        // timestamp earlier than prev — elapsed negative
        tx.timestamp = base - chrono::Duration::seconds(10);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"e\"")]);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        // age clamped to 0, so current_age=0 < s_max_age -> no violation even though
        // the conditional header is present
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_s_max_age_enforcement"
                ]),
            )
            .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_s_max_age_enforcement");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
