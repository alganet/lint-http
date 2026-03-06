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
/// pre-date the capture) are ignored, and the similar `stateful_cookie_lifecycle`
/// rule already handles path mismatches and secure-cookie checks, so in
/// practice this rule mostly catches domain‑mismatch cases that the other rule
/// misses.
pub struct StatefulCookieDomainMatching;

impl Rule for StatefulCookieDomainMatching {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_cookie_domain_matching"
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

            if domain_mismatch {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Cookie '{}' with value '{}' was set for a different domain and should not be sent to host '{}'",
                        name, value, req_host
                    ),
                });
            }

            if path_mismatch {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Cookie '{}' with value '{}' is not valid for path '{}'",
                        name, value, req_path
                    ),
                });
            }

            // otherwise the cookie is unknown to our history; skip
        }

        None
    }
}

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
        });
        if let Some(ts) = timestamp {
            tx.timestamp = ts;
        }
        tx
    }

    #[test]
    fn no_violation_without_history() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req("https://example.com/", Some("foo=1"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn valid_cookie_allowed() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/foo", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn domain_mismatch_flagged() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("different domain"));
    }

    #[test]
    fn domain_mismatch_but_value_matches_valid_cookie_not_flagged() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let history =
            crate::transaction_history::TransactionHistory::new(vec![prev2.clone(), prev1.clone()]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn path_mismatch_flagged() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/private"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn no_cookie_header_ignored() {
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req("https://example.com/", None);
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn unrelated_value_ignored() {
        // history has a cookie with same name but different value for another
        // domain; sending a different value should not trigger.
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=2"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn http_scheme_valid_cookie() {
        // non-secure cookie should still be allowed over plain HTTP when domain/path match
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx("http://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("http://example.com/foo", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn secure_cookie_over_http_not_flagged() {
        // scheme logic should ensure secure cookies are simply ignored by this rule
        let rule = StatefulCookieDomainMatching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Secure; Path=/"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("http://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_cookie_domain_matching");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }
}
