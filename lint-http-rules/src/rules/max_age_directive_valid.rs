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
/// This stateful check complements the stateless `cached_validators_reused` rule
/// (which merely ensures that conditional headers are included when validators
/// exist) by tying the presence of those headers to the actual freshness
/// lifetime of a cached response.
pub struct MaxAgeDirectiveValid;

impl Rule for MaxAgeDirectiveValid {
    fn id(&self) -> &'static str {
        "max_age_directive_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // examines both request and past responses
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // locate most recent prior response with a usable max-age
        let mut candidate: Option<(&crate::http_transaction::HttpTransaction, i64)> = None;

        for past in history.iter() {
            if let Some(resp) = &past.response {
                // The helper owns the directive parse. Two of its behaviours matter
                // here: it returns None when no-cache or no-store is also present —
                // which is what this rule wants, since under those directives
                // revalidating is required rather than wasteful — and it reads the
                // value with an integer parse, so a max-age too large for i64 yields
                // None and the resource is skipped rather than treated as long-lived.
                if let Some(max_age) =
                    crate::helpers::headers::get_cache_control_max_age(&resp.headers)
                {
                    candidate = Some((past, max_age));
                    break;
                }
            }
        }

        let (prev_tx, max_age) = candidate?;

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
        if current_age < max_age {
            if has_conditional {
                // Efficiency heuristic, not a violation: no sentence forbids revalidating
                // early. §4.2 frames reuse-while-fresh as an opportunity ("can"), so a
                // conditional request inside the freshness window is a wasted round-trip
                // — which is what this reports. (`immutable` is the one directive that
                // turns this into a SHOULD NOT, and that is a separate rule.)
                // cite(RFC 9111 § 4.2): "When a response is fresh, it can be used to satisfy subsequent requests without contacting the origin server, thereby improving efficiency"
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
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
                // Also an efficiency heuristic: §4.3 says a cache that cannot serve a
                // stored response *can* revalidate, not that it must. Refetching
                // unconditionally is legal — it just discards the validator already held
                // and the 304 it could have earned.
                // cite(RFC 9111 § 4.3): "it can use the conditional request mechanism"
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: format!(
                        "Stale cached entry (age {} >= max-age {}) refetched without a conditional request, though a validator was available to revalidate with",
                        current_age, max_age
                    ),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful max-age directive validity")
    }

    fn description(&self) -> &'static str {
        "Responses tagged with a `Cache-Control` `max-age=<seconds>` directive promise that the representation may safely be reused without revalidation for `<seconds>` seconds after it was stored.  Caches and clients that ignore this lifespan risk serving stale content or incurring unnecessary round‑trips.\n\nThis rule reconstructs a very small piece of cache state for a given client+resource by examining the most recent prior response that included a parseable `max-age` directive.  It then computes an approximate \"age\" for that stored response using any `Age` header it carried plus the time elapsed since it was observed.\n\nTwo types of violations are reported:\n\n* Sending a **conditional request** (`If-None-Match` or `If-Modified-Since`) while the cached copy is still fresh (age < max‑age).  Revalidation at this point is a redundant round‑trip: a fresh response can be reused without contacting the origin at all.\n* Issuing an **unconditional request** after the cached entry has become stale (age > max‑age) *when the prior response provided a validator (ETag or Last-Modified)*.  Refetching in full discards the validator already held, and with it the chance of a small `304`. (Clients that lack a validator are simply forced to fetch anew, which is not flagged.)\n\nBoth are efficiency findings rather than protocol violations: RFC 9111 frames fresh reuse and conditional revalidation as things a cache *can* do, not obligations.  The exception is `Cache-Control: immutable`, which does turn early revalidation into a SHOULD NOT; that is checked by a separate rule.\n\nThe stateful check augments the stateless [`cached_validators_reused`](cached_validators_reused.md) rule, which merely ensures conditional headers are included when validators exist regardless of age."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
                note: "Freshness — fresh/stale definitions, and reuse without contacting the origin as an efficiency opportunity (age itself is calculated per §4.2.3)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3",
                note: "Validation — a cache that cannot serve a stored response can use a conditional request to revalidate it",
            },
        ]
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
                compliance: Compliance::NonCompliant,
                label: Some("— unnecessary revalidation while still fresh"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=60\n< ETag: \"v1\"\n\n# ten seconds later, client inexplicably revalidates\n> GET /data HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # age 10 < 60, should not revalidate yet",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— stale entry reused without conditional request"),
                snippet: "> GET /data HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1\n< ETag: \"v1\"\n\n# several seconds later the client fetches again but omits validators\n> GET /data HTTP/1.1\n> Host: example.com\n# violation: stale age but no conditional header",
            },
        ]
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

    #[test]
    fn boundary_age_equal_unconditional_reports() {
        let rule = MaxAgeDirectiveValid;
        let base = Utc::now();

        // age == max-age should count as stale
        let prev =
            make_prev_with_headers(&[("cache-control", "max-age=10"), ("etag", "\"a\"")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("still fresh"));
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

    #[test]
    fn stale_unconditional_reports_when_validator_present() {
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Stale cached entry"));
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

    #[test]
    fn age_header_makes_stale_unconditional() {
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
        assert!(
            v.is_some(),
            "should flag stale unconditional with age header"
        );
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
        // age == max-age should be treated as stale; unconditional request
        // should therefore be flagged since validator exists.
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["max_age_directive_valid"]),
        );
        assert!(v.is_some(), "unconditional fetch at boundary should warn");

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
        crate::test_helpers::enable_rule(&mut cfg, "max_age_directive_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
