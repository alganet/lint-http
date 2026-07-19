// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that responses marked `no-cache` are not reused without performing
/// a conditional revalidation when a validator is available.
///
/// The `no-cache` directive (RFC 9111 §5.2.2.5) permits a cache to store a
/// response but requires the cache to submit a request to the origin server and
/// successfully validate the stored entry before using it to satisfy a
/// subsequent request.  In practical terms this means that if a prior response
/// for the same resource included `Cache-Control: no-cache` and also contained
/// at least one validator (`ETag` or `Last-Modified`), then any later request
/// for that resource **should** include a corresponding conditional header
/// (`If-None-Match` or `If-Modified-Since`).  A bare unconditional request is
/// evidence that the client may have reused the cached entry without
/// revalidation.
///
/// This stateful rule scans the transaction history (which the engine already
/// scopes to the same client+URI) and locates the most recent response that
/// carried a `no-cache` directive.  If that response also provided a validator
/// and the current request is unconditional, the rule emits a violation.
///
/// The check is intentionally conservative: it does **not** attempt to
/// distinguish between a cache reuse and a normal fresh fetch, and it does not
/// inspect request-side `Cache-Control: no-cache` clauses.  The presence of a
/// validator is required so that the rule does not warn on responses that
/// could not possibly be revalidated.
pub struct StatefulNoCacheRevalidation;

impl Rule for StatefulNoCacheRevalidation {
    fn id(&self) -> &'static str {
        "stateful_no_cache_revalidation"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // examines both the request and prior responses for the same
        // client+resource (history is filtered by the engine accordingly).
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // locate the most recent past response with a no-cache directive.
        let mut candidate: Option<&crate::http_transaction::HttpTransaction> = None;
        for past in history.iter() {
            if let Some(resp) = &past.response {
                if header_has_no_cache(&resp.headers) {
                    candidate = Some(past);
                    break;
                }
            }
        }

        let prev_tx = candidate?;

        // only warn if the original response supplied a validator; without one
        // there is no way to perform a conditional revalidation, so an
        // unconditional request may still be legitimate.
        let resp = prev_tx.response.as_ref().unwrap();
        let has_validator =
            resp.headers.contains_key("etag") || resp.headers.contains_key("last-modified");
        if !has_validator {
            return None;
        }

        let has_conditional = tx.request.headers.contains_key("if-none-match")
            || tx.request.headers.contains_key("if-modified-since");

        // cite(RFC 9111 § 5.2.2.4): "The no-cache response directive, in its unqualified form (without an argument), indicates that the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
        if !has_conditional {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Possible reuse of response marked 'no-cache' without conditional revalidation: subsequent request lacked If-None-Match/If-Modified-Since despite earlier no-cache response with a validator".into(),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful no-cache revalidation")
    }

    fn description(&self) -> &'static str {
        "The `no-cache` cache-control directive (RFC 9111 §5.2.2.5) permits a cache to store a response, but it **must not** use that stored entry to satisfy a subsequent request without first validating it with the origin server.  In practice, caches are expected to issue a conditional request using a validator (usually an `ETag` or `Last-Modified` value) when they have one; if no validator is available the cache may perform an unconditional request, which still contacts the origin server.\n\nThis stateful rule reconstructs a small portion of cache state for the current client+resource by locating the most recent prior response that included `Cache-Control: no-cache`.  If that response also carried a validator and the current request is unconditional (no `If-None-Match` or `If-Modified-Since` headers), the rule emits a warning.  The presence of validators is required to avoid false alarms in cases where the entry could not possibly be revalidated.\n\nThe check deliberately ignores request-side `Cache-Control: no-cache` clauses and makes no attempt to calculate freshness; it simply tracks whether a conditional header was omitted.  This rule complements `stateful_max_age_directive_validity` and `stateful_must_revalidate_enforcement` by focussing on the specific behaviour mandated by the `no-cache` directive."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.2.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4",
                note: "`no-cache`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
                note: "Calculating the age of a response (background context)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— conditional request satisfies no-cache requirement"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n< ETag: \"v1\"\n\n# later:\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"    # conditional request used; no violation",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— no validator means unconditional request is acceptable"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n\n# client cannot compose a conditional request; unconditional fetch is fine\n> GET /resource HTTP/1.1\n> Host: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— reused entry without revalidation"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: no-cache\n< ETag: \"v1\"\n\n# later, client repeats request but omits validator\n> GET /resource HTTP/1.1\n> Host: example.com\n# violation: cached response required conditional revalidation",
            },
        ]
    }
}

/// Look for a `no-cache` directive in any Cache-Control header field.
fn header_has_no_cache(headers: &hyper::HeaderMap) -> bool {
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            for directive in s.split(|c| [',', ';'].contains(&c)) {
                let directive = directive.trim();
                if directive.is_empty() {
                    continue;
                }
                // Support both bare `no-cache` and parameterised forms like
                // `no-cache="field-name"` by comparing only the directive name.
                let name = directive.split('=').next().map(str::trim).unwrap_or("");
                if name.eq_ignore_ascii_case("no-cache") {
                    return true;
                }
            }
        }
    }
    false
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulNoCacheRevalidation;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev(headers: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, headers);
        tx.request.method = "GET".to_string();
        tx
    }

    #[test]
    fn no_history_no_violation() {
        let rule = StatefulNoCacheRevalidation;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_no_cache_revalidation",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_cache_parsing_variants() {
        // basic case-insensitive match
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("max-age=0, no-cache"),
        );
        assert!(header_has_no_cache(&headers));
        // different casing and extra whitespace
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("  NO-CACHE  "),
        );
        assert!(header_has_no_cache(&headers));
        // semicolon as a separator and quoted arguments
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("private; no-cache=\"field\""),
        );
        assert!(header_has_no_cache(&headers));
        // negative control: header present but no no-cache directive
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("max-age=60, public"),
        );
        assert!(!header_has_no_cache(&headers));
    }

    #[test]
    fn no_cache_unconditional_flagged() {
        let rule = StatefulNoCacheRevalidation;
        // `no-cache` responses without a validator should not trigger a
        // violation (see `no_validator_no_violation`), so include a validator
        // here to exercise the warning path.
        let mut prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_no_cache_revalidation",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("no-cache"));
    }

    #[test]
    fn conditional_after_no_cache_allowed() {
        let rule = StatefulNoCacheRevalidation;
        let mut prev = make_prev(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_no_cache_revalidation"
                ]),
            )
            .is_none());
    }

    #[test]
    fn no_validator_no_violation() {
        let rule = StatefulNoCacheRevalidation;
        let mut prev = make_prev(&[("cache-control", "no-cache")]);
        prev.request.uri = "/resource".to_string();
        prev.client = crate::test_helpers::make_test_client();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.uri = "/resource".to_string();

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_no_cache_revalidation"
                ]),
            )
            .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_no_cache_revalidation");
        // Enabling the rule with a valid config must pass validation.
        crate::rules::validate_rules(&cfg).unwrap();
        // Ensure the rule is registered in the global RULES registry.
        assert!(crate::rules::RULES
            .iter()
            .any(|rule| rule.id() == "stateful_no_cache_revalidation"));
    }
}
