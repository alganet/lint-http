// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure cookies set via `Set-Cookie` are stored and sent correctly by the
/// client: expired cookies should not be included, updated cookies should
/// replace previous values, and secure cookies should not be leaked over HTTP.
///
/// This rule reconstructs a simple cookie store from the history of
/// `Set-Cookie` responses for the same origin, then compares that state with
/// the `Cookie` header on outgoing requests.
pub struct StatefulCookieLifecycle;

impl Rule for StatefulCookieLifecycle {
    fn id(&self) -> &'static str {
        "stateful_cookie_lifecycle"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // Observes client request headers only; does not examine server
        // behavior directly (other rules cover syntax).
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // only care about outgoing requests that carry Cookie headers
        let cookie_headers: Vec<_> = tx.request.headers.get_all("cookie").iter().collect();
        if cookie_headers.is_empty() {
            return None;
        }

        // parse request host, path, and scheme for matching
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

        // Grab a flat slice of history once so we don't re-allocate every
        // time we need to walk it.  `TransactionHistory::iter()` yields
        // &HttpTransaction in oldest-first order, so reversing it gives
        // newest-first which we later want when scanning for domain/path
        // reasons.
        let history_items: Vec<_> = history.iter().collect();

        // Build live cookie store using helper; it already filters out
        // expired entries up to the current request timestamp.
        let live_cookies = crate::helpers::cookie::build_cookie_store(history, tx.timestamp);

        // Parse cookie header(s) into name/value pairs.  Multiple header
        // fields are concatenated per RFC 6265 §4.2.
        let mut sent_pairs: Vec<(String, String)> = Vec::new();
        for hv in cookie_headers.iter() {
            if let Ok(s) = hv.to_str() {
                sent_pairs.extend(crate::helpers::cookie::parse_cookie_header(s));
            }
        }

        // examine each sent cookie for violations
        for (name, value) in sent_pairs {
            // search for the *best* applicable live cookie.  RFC 6265
            // specifies that user agents should include the cookie with the
            // most specific path (longest) when multiple match.  Domain
            // specificity is approximated by longer domain string (more
            // labels); history order is already taken into account when the
            // store was built.  Choose the candidate with the highest "score".
            let mut matching_live: Option<&crate::helpers::cookie::Cookie> = None;
            for c in &live_cookies {
                if c.name == name
                    && c.domain_matches(&req_host)
                    && c.path_matches(&req_path)
                    && (!c.secure || scheme == "https")
                {
                    let better = if let Some(existing) = matching_live {
                        let existing_score = (existing.path.len(), existing.domain.len());
                        let this_score = (c.path.len(), c.domain.len());
                        this_score > existing_score
                    } else {
                        true
                    };
                    if better {
                        matching_live = Some(c);
                    }
                }
            }

            // check for secure-over-http violation first.  Rather than just
            // looking for any stored secure cookie with the same name we
            // also compare the value, because the Cookie header omits
            // domain/path attributes.  Without the value check a more
            // specific non-secure cookie could be sent without warning, yet
            // the rule would still flag because a different secure cookie of
            // the same name exists.  Matching on (name,value) reduces false
            // positives; the following stale-value check will catch other
            // mismatches.
            if scheme != "https" {
                // only flag if the client actually sent the exact same
                // name/value pair we know was marked secure and applicable to
                // this request.
                if live_cookies.iter().any(|c| {
                    c.name == name
                        && c.value == value
                        && c.secure
                        && c.domain_matches(&req_host)
                        && c.path_matches(&req_path)
                }) {
                    // cite(RFC 6265 § 4.1.2.5): "The Secure attribute limits the scope of the cookie to "secure" channels"
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Secure cookie '{}' sent over insecure transport", name),
                    });
                }
            }

            if let Some(c) = matching_live {
                // live cookie exists; ensure value matches
                if c.value != value {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Cookie '{}' value '{}' does not match stored value '{}', likely stale",
                            name, value, c.value
                        ),
                    });
                }
            } else {
                // no live cookie.  inspect history to see why it isn't live:
                // * expired/removed (domain+path match), or
                // * path restriction prevented it while domain still matches.
                let mut seen_domain = false;
                let mut seen_path = false;
                for prev in history_items.iter().rev() {
                    if let Some(resp) = &prev.response {
                        for hv in resp.headers.get_all("set-cookie").iter() {
                            if let Ok(s) = hv.to_str() {
                                if let Some(cookie) = crate::helpers::cookie::parse_set_cookie(
                                    s,
                                    &prev.request.uri,
                                    prev.timestamp,
                                ) {
                                    if cookie.name == name && cookie.domain_matches(&req_host) {
                                        seen_domain = true;
                                        if cookie.path_matches(&req_path) {
                                            seen_path = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if seen_path {
                        break;
                    }
                }
                if seen_path {
                    // there was a matching cookie in the past but it is no longer
                    // live (either expired, deleted, or replaced by another). A client
                    // still sending it has a store the user agent was required to have
                    // emptied.
                    // cite(RFC 6265 § 5.3): "The user agent MUST evict all expired cookies from the cookie store if, at any time, an expired cookie exists in the cookie store."
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Cookie '{}' was previously set but is expired or removed and should not be sent",
                            name
                        ),
                    });
                }
                if seen_domain {
                    // a cookie existed for the domain but path did not match
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Cookie '{}' is not valid for path '{}' and should not be sent",
                            name, req_path
                        ),
                    });
                }
            }
            // otherwise, the cookie may predate our history; assume it's
            // legitimate and do not flag.
        }

        None
    }

    fn description(&self) -> &'static str {
        "Cookies sent by servers via the `Set-Cookie` header establish state that a client is expected to retain and present on subsequent requests. This rule reconstructs a simplistic cookie store for a given origin and verifies that outgoing requests are consistent with that store.  It flags three broad classes of client misbehaviour:\n\n* Sending cookies after they have clearly expired or been removed.\n* Continuing to send an old value after a newer cookie with the same name/domain/path has been observed.\n* Transmitting a cookie marked `Secure` over an insecure (HTTP) transport.  The rule only flags this if the actual name/value pair sent corresponds to a known secure cookie, which avoids false positives when a non‑secure cookie with the same name is used.\n\nThe check relies solely on the captured traffic for a given client+origin; if a cookie appears in a request but the linter has never seen it set in the past, the rule assumes it pre‑dates the capture and does not complain."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6265",
                section: Some("5"),
                url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5",
                note: "Storage model",
            },
            crate::rules::SpecRef {
                spec: "RFC 6265",
                section: Some("5.1.3"),
                url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3",
                note: "Domain matching",
            },
            crate::rules::SpecRef {
                spec: "RFC 6265",
                section: Some("5.1.4"),
                url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4",
                note: "Path matching",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: session=abc; Max-Age=3600; Path=/\n\n> GET /bar HTTP/1.1\n> Host: example.com\n> Cookie: session=abc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— different non-secure cookie over HTTP"),
                snippet: "> GET / HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=secure; Secure; Path=/\n\n> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=plain; Path=/foo\n\n> GET /foo HTTP/1.1\n> Host: example.com\n> Cookie: id=plain           # only the non-secure value is sent over HTTP",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— expired cookie sent"),
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: session=abc; Max-Age=1\n\n> GET /bar HTTP/1.1\n> Host: example.com\n> Cookie: session=abc        # sent five minutes later despite expiration",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— stale value"),
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=1; Path=/\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=2; Path=/\n\n> GET /baz HTTP/1.1\n> Host: example.com\n> Cookie: id=1               # old value should have been replaced",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— secure cookie over HTTP"),
                snippet: "> GET /login HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: sid=123; Secure\n\n> GET /dashboard HTTP/1.1\n> Host: example.com\n> Cookie: sid=123            # insecure transport",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulCookieLifecycle;

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
        let rule = StatefulCookieLifecycle;
        let tx = make_tx_with_req("https://example.com/", Some("foo=1"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_cookie_lifecycle"
                ]),
            )
            .is_none());
    }

    #[test]
    fn unrelated_cookie_ignored() {
        let rule = StatefulCookieLifecycle;
        let ts = chrono::Utc::now();
        // history contains a cookie named a
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("b=2"));
        tx.timestamp = ts + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_cookie_lifecycle"
                ]),
            )
            .is_none());
    }

    #[test]
    fn secure_cookie_over_https_ok() {
        let rule = StatefulCookieLifecycle;
        let ts = chrono::Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Secure"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn cookie_sent_within_lifetime() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Max-Age=60"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(30);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(rule
            .check_transaction(
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "stateful_cookie_lifecycle"
                ]),
            )
            .is_none());
    }

    #[test]
    fn expired_cookie_sent_flagged() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Max-Age=1"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("expired or removed"));
    }

    #[test]
    fn stale_value_flagged() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev1 = make_resp_tx("https://example.com/", Some("a=1; Max-Age=60"), Some(ts));
        let prev2 = make_resp_tx(
            "https://example.com/",
            Some("a=2; Max-Age=60"),
            Some(ts + chrono::Duration::seconds(10)),
        );
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(20);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            prev2.clone(),
            prev1.clone(),
        ]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("value"));
    }

    #[test]
    fn secure_cookie_over_http_flagged() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Secure"), Some(ts));
        let mut tx = make_tx_with_req("http://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Secure cookie"));
    }

    #[test]
    fn secure_cookie_different_value_not_flagged_over_http() {
        // simulate a secure cookie stored for path=/ and a later non-secure
        // cookie with the same name but a different value and a more
        // specific path.  The client sends only the non-secure value over
        // plain HTTP; the rule should *not* report a secure-over-http
        // violation (the sent pair doesn't actually match the secure cookie).
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev_secure = make_resp_tx(
            "https://example.com/",
            Some("a=1; Secure; Path=/"),
            Some(ts),
        );
        let prev_nonsecure = make_resp_tx(
            "https://example.com/specific",
            Some("a=2; Path=/specific"),
            Some(ts + chrono::Duration::seconds(1)),
        );
        let mut tx = make_tx_with_req("http://example.com/specific", Some("a=2"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            prev_nonsecure.clone(),
            prev_secure.clone(),
        ]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(
            v.is_none(),
            "should not flag secure cookie if sent value is different"
        );
    }

    #[test]
    fn path_mismatch_flagged() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/private"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn path_prefix_boundary_flagged() {
        // /foo should not match /foobar
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/foo"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/foobar", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn domain_mismatch_ignored() {
        let rule = StatefulCookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Domain=example.com"),
            Some(ts),
        );
        let mut tx = make_tx_with_req("https://other.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_cookie_lifecycle",
            ]),
        );
        // request to other.com should not be influenced by cookie from example.com
        assert!(
            v.is_none(),
            "cookie from different domain should be ignored"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_cookie_lifecycle");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
