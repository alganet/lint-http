// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure a client only attaches cookies to requests when the cookie's domain
/// (and path) attributes actually permit it.  A browser's cookie store should
/// restrict cookies to hosts that domain‑match the cookie's effective domain
/// and to request paths that satisfy the path‑matching algorithm in RFC 6265.
///
/// This rule is intentionally narrow; it only emits a warning when the exact
/// name/value pair seen in a `Cookie` header corresponds to a previously
/// observed `Set-Cookie` header whose attributes would not allow that value to
/// be sent for the current request URI.  Unknown cookies (e.g. ones that
/// pre-date the capture) are ignored, and the similar `cookie_lifecycle`
/// rule already handles path mismatches and secure-cookie checks, so in
/// practice this rule mostly catches domain‑mismatch cases that the other rule
/// misses.
pub struct CookieDomainMatching;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6265_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4",
    note: "The Cookie header (which cookies are sent)",
};
const RFC_6265_5_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3",
    note: "Domain matching",
};
const RFC_6265_5_1_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4",
    note: "Path matching",
};

impl Rule for CookieDomainMatching {
    fn id(&self) -> &'static str {
        "cookie_domain_matching"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            // only care about outgoing requests that carry Cookie headers
            let cookie_headers: Vec<_> = tx.request.headers.get_all("cookie").iter().collect();
            if cookie_headers.is_empty() {
                return None;
            }

            let req_uri = &tx.request.uri;
            let scheme = if req_uri.to_ascii_lowercase().starts_with("https://") {
                "https"
            } else {
                "http"
            };

            // host and path information used for matching
            let req_host =
                crate::helpers::uri::extract_host_from_request_target(req_uri).unwrap_or_default();
            let req_path = crate::helpers::uri::extract_path_from_request_target(req_uri)
                .unwrap_or_else(|| "/".into());

            // build live cookie store (expires removed) so we only inspect
            // currently applicable cookies
            let live_cookies = crate::helpers::cookie::build_cookie_store(history, tx.timestamp);

            // parse Cookie headers into name/value pairs
            let mut sent_pairs: Vec<(String, String)> = Vec::new();
            for hv in cookie_headers.iter() {
                if let Ok(s) = hv.to_str() {
                    sent_pairs.extend(crate::helpers::cookie::parse_cookie_header(s));
                }
            }

            for (name, value) in sent_pairs {
                let mut valid_match = false;
                let mut domain_mismatch = false;
                let mut path_mismatch = false;

                for c in &live_cookies {
                    if c.name != name || c.value != value {
                        continue;
                    }

                    // cookie value matches; now classify according to domain/path
                    if c.domain_matches(&req_host) {
                        if !c.path_matches(&req_path) {
                            path_mismatch = true;
                        } else if !c.secure || scheme == "https" {
                            valid_match = true;
                        }
                    } else {
                        domain_mismatch = true;
                    }
                }

                if valid_match {
                    continue;
                }

                // The domain-match and path-match *definitions* (§5.1.3, §5.1.4)
                // are owned by the helper's `domain_matches`/`path_matches`, which
                // this rule only calls. What this rule enforces is §5.4's decision
                // to *send*: a cookie the user agent puts in the Cookie header must
                // have met every requirement of the cookie-list, so a stored cookie
                // failing the domain requirement was never eligible to be sent.
                // cite(RFC 6265 § 5.4): "Let cookie-list be the set of cookies from the cookie store that meets all of the following requirements:"
                if domain_mismatch {
                    return Some(self.violation(ctx.severity, format!(
                            "Cookie '{}' with value '{}' was set for a different domain and should not be sent to host '{}'",
                            name, value, req_host
                        )));
                }

                // The path half of the same §5.4 cookie-list requirement; the
                // path-match predicate itself is the helper's (§5.1.4).
                // cite(RFC 6265 § 5.4): "The request-uri's path path-matches the cookie's path."
                if path_mismatch {
                    return Some(self.violation(
                        ctx.severity,
                        format!(
                            "Cookie '{}' with value '{}' is not valid for path '{}'",
                            name, value, req_path
                        ),
                    ));
                }

                // otherwise the cookie is unknown to our history; skip
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "A client should only send a cookie back to a server when the request URI satisfies the cookie's domain and path constraints.  Browsers build the `Cookie` header with the cookie-list algorithm of [RFC 6265 §5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4), which sends only cookies meeting the domain-match ([§5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3)) and path-match ([§5.1.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4)) requirements; this rule flags instances where the observed `Cookie` header contains a name/value pair that corresponds to a previously set cookie whose attributes would *not* allow it to be sent for the current host/path.\n\nTo avoid spurious warnings the check only considers cookies that have been seen in the capture history and matches on the exact value.  Unknown cookies are assumed to pre‑date the capture and are ignored.  The related `cookie_lifecycle` rule already handles path‑mismatch diagnostics and secure‑cookie checks; this rule is primarily intended to catch domain mismatches that the other rule overlooks."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_6265_5_4, RFC_6265_5_1_3, RFC_6265_5_1_4]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET / HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: session=abc; Path=/\n\n> GET /foo HTTP/1.1\n> Host: example.com\n> Cookie: session=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— domain mismatch"),
                snippet: "> GET / HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: sid=123; Domain=example.com\n\n> GET / HTTP/1.1\n> Host: other.com\n> Cookie: sid=123               # invalid; domain does not match",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— path mismatch (also flagged by cookie_lifecycle)"),
                snippet: "> GET / HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=1; Path=/private\n\n> GET /public HTTP/1.1\n> Host: example.com\n> Cookie: id=1                 # path does not match",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CookieDomainMatching;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_tx_with_req(
        uri: &str,
        cookie: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        if let Some(val) = cookie {
            tx.request
                .headers
                .append("Cookie", hyper::header::HeaderValue::from_str(val).unwrap());
        }
        tx
    }

    fn make_resp_tx(
        uri: &str,
        set_cookie: Option<&str>,
        timestamp: Option<chrono::DateTime<chrono::Utc>>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_tx_with_req(uri, None);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: match set_cookie {
                Some(sc) => crate::test_helpers::make_headers_from_pairs(&[("set-cookie", sc)]),
                None => crate::test_helpers::make_headers_from_pairs(&[]),
            },
            body_length: None,
            trailers: None,
        });
        if let Some(ts) = timestamp {
            tx.timestamp = ts;
        }
        tx
    }

    #[test]
    fn no_violation_without_history() {
        let rule = CookieDomainMatching;
        let tx = make_tx_with_req("https://example.com/", Some("foo=1"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn valid_cookie_allowed() {
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/foo", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn domain_mismatch_flagged() {
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("different domain"));
    }

    #[test]
    fn domain_mismatch_but_value_matches_valid_cookie_not_flagged() {
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev1 = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let prev2 = make_resp_tx(
            "https://other.com/",
            Some("a=1; Domain=other.com"),
            Some(ts + chrono::Duration::seconds(1)),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            prev2.clone(),
            prev1.clone(),
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn host_only_cookie_to_subdomain_flagged() {
        // A cookie set with no Domain attribute is "host-only" (RFC 6265 §5.3);
        // §5.4 permits sending it only when the request-host is *identical* to
        // the cookie's domain, so a client presenting it to a subdomain is
        // misbehaving and must be flagged.
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://sub.example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        );
        assert!(
            v.is_some(),
            "host-only cookie sent to a subdomain should be flagged"
        );
        assert!(v.unwrap().message.contains("different domain"));
    }

    #[test]
    fn domain_scoped_cookie_allowed_to_subdomain() {
        // With an explicit Domain attribute the cookie is NOT host-only and
        // does domain-match subdomains (RFC 6265 §5.1.3); it must stay allowed.
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com; Path=/"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://sub.example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn path_mismatch_flagged() {
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/private"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn no_cookie_header_ignored() {
        let rule = CookieDomainMatching;
        let tx = make_tx_with_req("https://example.com/", None);
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn unrelated_value_ignored() {
        // history has a cookie with same name but different value for another
        // domain; sending a different value should not trigger.
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=2"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn http_scheme_valid_cookie() {
        // non-secure cookie should still be allowed over plain HTTP when domain/path match
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx("http://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("http://example.com/foo", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn secure_cookie_over_http_not_flagged() {
        // scheme logic should ensure secure cookies are simply ignored by this rule
        let rule = CookieDomainMatching;
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Secure; Path=/"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("http://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_domain_matching"]),
        )
        .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cookie_domain_matching");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
