// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that responses for a given resource do not regress in their
/// representation date.  This is a heuristic, not a direct spec check: RFC 9111
/// §4.2.4 forbids a cache from generating a *stale* response, but it defines
/// "stale" against the §4.2 freshness calculation, which this rule never
/// performs.  Instead we approximate the observable symptom — a later response
/// carrying an older representation timestamp than one already seen for the
/// same URI — by computing a simple timestamp from the `Last-Modified` header
/// (RFC 9110 §8.8.2, the representation's own modification time) or, failing
/// that, the `Date` header (RFC 9110 §6.6.1, only the message's origination
/// time, a coarser proxy).  It examines neither validators such as `ETag` nor the Vary
/// secondary key, so URI identity is itself an approximation of the cache key.
pub struct CacheCoherence;

impl Rule for CacheCoherence {
    fn id(&self) -> &'static str {
        "cache_coherence"
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // ignore 304 responses, they have no representation body of their own
        // cite(RFC 9110 § 15.4.5): "there is no need for the server to transfer a representation of the target resource because the request indicates that the client, which made the request conditional, already has a valid representation"
        if resp.status == 304 {
            return None;
        }

        // helper to extract a "representation time" from headers.  We prefer
        // Last-Modified but fall back to Date.  Return None if neither can be
        // parsed.
        fn rep_time(headers: &hyper::HeaderMap) -> Option<chrono::DateTime<chrono::Utc>> {
            // Prefer Last-Modified: it timestamps the *representation* itself, so
            // a decrease directly signals the representation went backwards. The
            // HTTP-date grammar is owned by the parse helper (§5.6.7).
            // cite(RFC 9110 § 8.8.2): "The "Last-Modified" header field in a response provides a timestamp indicating the date and time at which the origin server believes the selected representation was last modified"
            if let Some(hv) = headers.get("last-modified") {
                if let Ok(s) = hv.to_str() {
                    if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                        return Some(dt);
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
            // URI identity stands in for the cache key. This is an
            // approximation: a real key also folds in the request method and
            // the Vary secondary key (RFC 9111 §4.1), neither of which is consulted
            // here, so two responses varying legitimately on, e.g., Accept can
            // be compared as if they were the same representation.
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

        // A representation going backwards in time across two responses is the observable
        // form of a cache serving something it should have revalidated. §4.2.4's MUST NOT
        // is the requirement this heuristic stands in for: we cannot compute §4.2 freshness
        // (no age or lifetime here), so a strictly-older timestamp is our proxy for "stale".
        // cite(RFC 9111 § 4.2.4): "A cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly permitted by the client or origin server"
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

    fn description(&self) -> &'static str {
        "Cache coherence ensures that once a newer representation of a resource is\navailable, earlier (stale) copies are not inadvertently served without\nrevalidation or invalidation.  Misconfigured caches or origin servers may\nreturn an older version of a document after a newer one has been observed.\n\nThis rule reconstructs a simple timeline for each resource observed by the\nclient.  Each response is assigned a timestamp derived from its\n`Last-Modified` header if present, otherwise from the `Date` header.  If a\nsubsequent response for the *same URI* carries a timestamp that is strictly\nolder than one seen previously, we report a violation — the later response\nappears to be serving a stale representation.\n\nOnly transactions whose response contains a parseable HTTP-date are\nexamined; missing or unparseable headers are ignored.  304 Not Modified\nresponses are skipped since they do not convey a new representation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4",
                note: "Serving Stale Responses — the MUST NOT this rule heuristically approximates",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.8.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
                note: "Last-Modified — the representation's modification time (preferred signal)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1",
                note: "Date — the message's origination time (coarser fallback signal)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
                note: "304 Not Modified — conveys no representation, so it is skipped",
            },
        ]
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
        assert!(v.unwrap().message.contains("appears stale"));
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

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cache_coherence");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
