// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

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
pub struct ImmutableCacheNeverStale;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_8246_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8246",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc8246.html#section-2",
    note: "The Immutable Cache-Control Extension — the directive definition and its SHOULD NOT-revalidate-while-fresh behavior",
};
const RFC_9111_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
    note: "Freshness — Calculating Freshness Lifetime (§4.2.1) and Calculating Age (§4.2.3)",
};

impl RuleMeta for ImmutableCacheNeverStale {
    fn id(&self) -> &'static str {
        "immutable_cache_never_stale"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful immutable cache never stale")
    }

    fn description(&self) -> &'static str {
        "The `immutable` cache-control directive (RFC 8246) signals that the representation is not expected to change.  Clients and caches are therefore encouraged to treat the response as fresh for the duration of its advertised freshness lifetime and to avoid revalidation during that period.  Revalidating (issuing a conditional request) while the entry is still fresh is wasteful and undermines the purpose of `immutable`.\n\nThis rule reconstructs a small piece of cache state for a given client and resource by locating the most recent prior response bearing an `immutable` directive that does not simultaneously forbid caching (`no-store` or `no-cache`).  It estimates the \"age\" of that response using any `Age` header and the elapsed time since the response was observed.  The advertised freshness lifetime is computed using the shared helper in `helpers::headers`, which honours `Cache-Control: max-age` and falls back to an `Expires` header if necessary.  If a subsequent request for the same resource includes a conditional header (`If-None-Match` or `If-Modified-Since`) **and** the calculated age is still less than the freshness lifetime, a warning is produced.  Unconditional requests and conditional requests made after the freshness lifetime expires are permitted, since `immutable` entries may still be reused without revalidation once stale."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_8246_2, RFC_9111_4_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— fresh response reused without revalidation"),
                snippet: "> GET /static.css HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=3600, immutable\n\n# thirty seconds later the cache is still fresh; no conditional request is sent",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— conditional request after expiry is allowed"),
                snippet: "> GET /static.css HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=1, immutable\n< ETag: \"v1\"\n\n# later, after expiry:\n> GET /static.css HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # revalidation after freshness is fine",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— unnecessary revalidation while still fresh"),
                snippet: "> GET /image.png HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: max-age=600, immutable\n< ETag: \"a\"\n\n# still within the advertised lifetime\n> GET /image.png HTTP/1.1\n> Host: example.com\n> If-None-Match: \"a\"        # unnecessary conditional request",
            },
        ]
    }
}

impl Rule for ImmutableCacheNeverStale {
    fn scope(&self) -> crate::rules::RuleScope {
        // Both: the rule correlates a client's conditional request with a prior
        // origin response that carried immutable, so it needs to see each side.
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
            // The most recent prior response with an immutable directive that
            // isn't simultaneously forbidding caching.
            let (prev_tx, prev_resp) =
                history.latest_response(|resp| header_has_immutable(&resp.headers))?;

            // Advertised freshness lifetime. The max-age/Expires calculation
            // (RFC 9111 §4.2.1) is owned by the helper, which carries the cite.
            let freshness_lifetime = crate::helpers::cache_control::compute_freshness_lifetime(
                &prev_resp.headers,
                prev_tx.timestamp,
            );

            // Age stated by the response plus the time it has since spent in our
            // record; the helper owns that estimate and what it leaves out.
            let current_age = crate::helpers::cache_control::estimated_age(
                &prev_resp.headers,
                prev_tx.timestamp,
                tx.timestamp,
            );

            // Only the two revalidation preconditions count as "revalidation" here:
            // If-None-Match and If-Modified-Since are what a cache sends to revalidate.
            // If-Match / If-Unmodified-Since are update preconditions, not cache
            // revalidation, so their presence is not the waste this rule targets.
            let has_conditional = tx.request.headers.contains_key("if-none-match")
                || tx.request.headers.contains_key("if-modified-since");

            // Only while fresh. `immutable` says nothing about a stale response, and this rule
            // must not either — hence the age check guarding the branch.
            // cite(RFC 8246 § 2): "Clients SHOULD NOT issue a conditional request during the response's freshness lifetime (e.g., upon a reload) unless explicitly overridden by the user (e.g., a force reload)."
            // cite(RFC 8246 § 2): "The immutable extension only applies during the freshness lifetime of the stored response."
            if has_conditional && current_age < freshness_lifetime {
                return Some(self.cited(&RFC_8246_2, ctx.severity, format!(
                        "Unnecessary revalidation of immutable response while still fresh (age {} < freshness {})",
                        current_age, freshness_lifetime
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Detect the presence of `immutable` in Cache-Control headers.  We ignore
/// values that also forbid caching (`no-store` or `no-cache`).
fn header_has_immutable(headers: &hyper::HeaderMap) -> bool {
    // Exclude responses that no-store or no-cache: under no-store nothing is
    // stored, so there is no cached entry for a later request to reuse; under
    // no-cache a conditional (validation) request is required before reuse, so
    // sending one is expected, not the wasteful revalidation this rule flags.
    // Either way there is no "fresh immutable entry reused without revalidation"
    // to reason about. (Substring match is deliberately coarse — a false skip on
    // a value that merely contains the text is safe, since it only suppresses a
    // best-effort warning.)
    // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request"
    // cite(RFC 9111 § 5.2.2.4): "the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
    if crate::helpers::cache_control::forbids_storage_or_reuse(headers) {
        return false;
    }
    // The immutable directive (RFC 8246 §2) takes no argument.
    crate::helpers::cache_control::has_unqualified(headers, "immutable")
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ImmutableCacheNeverStale;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction_with_response;
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
        let rule = ImmutableCacheNeverStale;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unrelated_history_ignored() {
        let rule = ImmutableCacheNeverStale;
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], Utc::now());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn fresh_conditional_reports_violation() {
        let rule = ImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unnecessary revalidation"));
    }

    #[test]
    fn boundary_age_conditional_allowed() {
        let rule = ImmutableCacheNeverStale;
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
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale"
            ]),
        )
        .is_none());
    }

    #[test]
    fn stale_conditional_ok() {
        let rule = ImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=1, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.timestamp = base + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale"
            ]),
        )
        .is_none());
    }

    #[test]
    fn no_immutable_skips() {
        let rule = ImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale"
            ]),
        )
        .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "immutable_cache_never_stale");
        crate::rules::validate_rules(&cfg).unwrap();
    }

    #[test]
    fn unconditional_fresh_no_violation() {
        let rule = ImmutableCacheNeverStale;
        let base = Utc::now();
        // previous immutable response fresh for 60s
        let prev = make_prev_with_headers(&[("cache-control", "max-age=60, immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale",
            ]),
        );
        assert!(v.is_none(), "unconditional fresh use should not warn");
    }

    #[test]
    fn conditional_with_age_and_negative_elapsed() {
        let rule = ImmutableCacheNeverStale;
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
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        // age_val=5, elapsed clamped to 0 -> current_age=5 < freshness(50) => violation
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale",
            ]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn conditional_no_freshness_skips() {
        let rule = ImmutableCacheNeverStale;
        let base = Utc::now();
        let prev = make_prev_with_headers(&[("cache-control", "immutable")], base);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v\"")]);
        tx.timestamp = base + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        // freshness lifetime zero, so no violation should be reported
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "immutable_cache_never_stale"
            ]),
        )
        .is_none());
    }
}
