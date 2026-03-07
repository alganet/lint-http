// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Enforce the semantics of the `SameSite` cookie attribute when cookies are
/// attached to outgoing requests.  A client should not include `Strict` or
/// `Lax` cookies in a cross-site context except where the Lax rules explicitly
/// permit top‑level navigations with safe methods.  Cookies with no attribute
/// (or an unrecognised value) are treated as `Lax` per modern defaults.
///
/// The rule relies on `Sec-Fetch-Site` and `Sec-Fetch-Mode` headers to
/// approximate the navigation context; if the site relationship is unknown the
/// check is skipped to avoid spurious warnings.
pub struct StatefulCookieSameSiteEnforcement;

impl Rule for StatefulCookieSameSiteEnforcement {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_cookie_same_site_enforcement"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // only care about outgoing requests that carry Cookie headers
        let cookie_headers: Vec<_> = tx.request.headers.get_all("cookie").iter().collect();
        if cookie_headers.is_empty() {
            return None;
        }

        // compute simple request metadata needed for matching
        let req_uri = &tx.request.uri;
        let scheme = if req_uri.to_ascii_lowercase().starts_with("https://") {
            "https"
        } else {
            "http"
        };

        // extract host portion (without port) using shared helper
        let req_host =
            crate::helpers::uri::extract_host_from_request_target(req_uri).unwrap_or_default();

        let req_path = crate::helpers::uri::extract_path_from_request_target(req_uri)
            .unwrap_or_else(|| "/".into());

        // determine site relationship; None means unknown and we skip enforcement
        let is_cross =
            match crate::helpers::headers::get_header_str(&tx.request.headers, "sec-fetch-site") {
                Some("same-origin") | Some("same-site") => false,
                Some("cross-site") => true,
                // `none` means there is no initiator site (e.g., user‑initiated
                // top‑level navigation). Treat it as unknown and skip enforcement
                // to avoid false positives.
                Some("none") => return None,
                _ => return None,
            };

        // allow sending of Lax cookies in top-level safe navigations
        let allow_lax = {
            let method = tx.request.method.as_str();
            let fetch_mode =
                crate::helpers::headers::get_header_str(&tx.request.headers, "sec-fetch-mode");
            // RFC draft allows GET/HEAD navigation requests
            let safe_method = matches!(method, "GET" | "HEAD");
            safe_method && fetch_mode == Some("navigate")
        };

        // build live cookie store for origin at transaction time
        let live_cookies = crate::helpers::cookie::build_cookie_store(history, tx.timestamp);

        // parse sent cookies into pairs
        let mut sent_pairs: Vec<(String, String)> = Vec::new();
        for hv in cookie_headers.iter() {
            if let Ok(s) = hv.to_str() {
                sent_pairs.extend(crate::helpers::cookie::parse_cookie_header(s));
            }
        }

        // examine each sent cookie against its stored metadata
        for (name, value) in sent_pairs {
            // look for the most specific applicable live cookie with exact name/value
            let candidate = live_cookies
                .iter()
                .filter(|c| {
                    c.name == name
                        && c.value == value
                        && c.domain_matches(&req_host)
                        && c.path_matches(&req_path)
                        && (!c.secure || scheme == "https")
                })
                .max_by(|a, b| {
                    // Prefer longer path; on tie, prefer more specific (longer) domain.
                    let a_path_len = a.path.len();
                    let b_path_len = b.path.len();
                    a_path_len.cmp(&b_path_len).then_with(|| {
                        let a_domain_len = a.domain.as_str().len();
                        let b_domain_len = b.domain.as_str().len();
                        a_domain_len.cmp(&b_domain_len)
                    })
                });
            if let Some(c) = candidate {
                // determine effective SameSite value (default Lax)
                let effective = match c.same_site {
                    crate::helpers::cookie::SameSite::Strict => {
                        crate::helpers::cookie::SameSite::Strict
                    }
                    crate::helpers::cookie::SameSite::Lax => crate::helpers::cookie::SameSite::Lax,
                    crate::helpers::cookie::SameSite::None => {
                        crate::helpers::cookie::SameSite::None
                    }
                    crate::helpers::cookie::SameSite::Unspecified => {
                        crate::helpers::cookie::SameSite::Lax
                    }
                };

                if is_cross {
                    match effective {
                        crate::helpers::cookie::SameSite::Strict => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Cookie '{}' has SameSite=Strict but is sent in a cross-site context",
                                    name
                                ),
                            });
                        }
                        crate::helpers::cookie::SameSite::Lax => {
                            if !allow_lax {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Cookie '{}' has SameSite=Lax but is sent in a restricted cross-site context",
                                        name
                                    ),
                                });
                            }
                        }
                        _ => { /* None is allowed */ }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        make_headers_from_pairs, make_test_rule_config, make_test_transaction,
    };
    use chrono::Utc;
    use hyper::header::HeaderValue;

    fn make_tx_with_req(
        uri: &str,
        cookie: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_test_transaction();
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
                Some(sc) => make_headers_from_pairs(&[("set-cookie", sc)]),
                None => make_headers_from_pairs(&[]),
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
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let mut tx = make_tx_with_req("https://example.com/", Some("foo=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn request_without_cookie_header_skips() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let mut tx = make_test_transaction();
        tx.request.uri = "https://example.com/".to_string();
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(Utc::now()),
        )]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn fetch_site_none_skips() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("none"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn fetch_site_invalid_skips() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("invalid"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn unrelated_cookie_does_not_report() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        // history sets cookie b; request sends cookie a
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("b=1; SameSite=Strict"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn secure_cookie_over_http_ignored_for_samesite() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "http://example.com/",
            Some("a=1; SameSite=Strict; Secure"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("http://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        // even though cross-site, the secure cookie should not match because of scheme
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn strict_cookie_cross_site_reports() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        // history sets a Strict cookie
        let ts = Utc::now();
        let htx = make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(ts),
        );
        let history = crate::transaction_history::TransactionHistory::new(vec![htx]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn lax_cookie_cross_site_non_nav_reports() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Lax"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        // not a navigation
        tx.request
            .headers
            .append("sec-fetch-mode", HeaderValue::from_static("cors"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn lax_cookie_cross_site_nav_get_allowed() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Lax"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        tx.request
            .headers
            .append("sec-fetch-mode", HeaderValue::from_static("navigate"));
        tx.request.method = "GET".parse().unwrap();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn lax_cookie_cross_site_nav_head_allowed() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Lax"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        tx.request
            .headers
            .append("sec-fetch-mode", HeaderValue::from_static("navigate"));
        tx.request.method = "HEAD".parse().unwrap();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn none_cookie_cross_site_allowed() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=None; Secure"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn unspecified_treated_as_lax() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        tx.request
            .headers
            .append("sec-fetch-mode", HeaderValue::from_static("cors"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_some());
    }

    #[test]
    fn missing_fetch_site_skips() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let tx = make_tx_with_req("https://example.com/", Some("a=1"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_cookie_same_site_enforcement");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }

    #[test]
    fn same_site_context_allows_strict() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("same-site"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn mismatched_cookie_value_does_not_report() {
        let rule = StatefulCookieSameSiteEnforcement;
        let cfg = make_test_rule_config();
        let ts = Utc::now();
        let history = crate::transaction_history::TransactionHistory::new(vec![make_resp_tx(
            "https://example.com/",
            Some("a=1; SameSite=Strict"),
            Some(ts),
        )]);
        let mut tx = make_tx_with_req("https://example.com/", Some("a=2"));
        tx.request
            .headers
            .append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }
}
