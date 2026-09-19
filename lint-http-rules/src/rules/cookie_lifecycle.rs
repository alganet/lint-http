// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::{
    COOKIE_SCOPE_IGNORED, COOKIE_SECURE_IGNORED, COOKIE_VALUE_CONFLICTING, RFC_6265_5_1_3,
    RFC_6265_5_3, RFC_6265_5_4,
};
use crate::violations::ViolationDef;

/// Path matching, which is where `path-matches` is defined for the algorithm
/// § 5.4 runs and for the store this rule keeps.
const RFC_6265_5_1_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4",
    note:
        "Paths and Path-Match — the comparison § 5.4's first step runs a request-uri's path through",
};

/// Three entries, and all three are the *user agent's* rather than the
/// server's — which is what makes them the first `cookie` entries about the
/// `Cookie` field instead of the `Set-Cookie` one.
///
/// § 5.4's algorithm decides which stored cookies a request may carry, and two
/// of these are cookies it excludes: one whose `Secure` attribute the scheme
/// contradicts, and one the store should not have offered at all. The third is
/// a value this exchange never set, which no sentence forbids and which the
/// entry marks as the heuristic it is.
static DECLARED: &[&ViolationDef] = &[
    &COOKIE_SECURE_IGNORED,
    &COOKIE_SCOPE_IGNORED,
    &COOKIE_VALUE_CONFLICTING,
];

/// Ensure cookies set via `Set-Cookie` are stored and sent correctly by the
/// client: expired cookies should not be included, updated cookies should
/// replace previous values, and secure cookies should not be leaked over HTTP.
///
/// This rule reconstructs a simple cookie store from the history of
/// `Set-Cookie` responses for the same origin, then compares that state with
/// the `Cookie` header on outgoing requests.
pub struct CookieLifecycle;

/// The request a cookie is being sent on, in the three terms a cookie is
/// matched against.
struct RequestScope {
    scheme: String,
    host: String,
    path: String,
}

impl RequestScope {
    fn of(request_uri: &str) -> Self {
        Self {
            scheme: if request_uri.to_ascii_lowercase().starts_with("https://") {
                "https".into()
            } else {
                "http".into()
            },
            host: crate::helpers::request_target::extract_host_from_request_target(request_uri)
                .unwrap_or_default(),
            path: crate::helpers::request_target::extract_path_from_request_target(request_uri)
                .unwrap_or_else(|| "/".into()),
        }
    }

    /// Whether a stored cookie would be sent on this request.
    // cite(RFC 6265 § 5.4): "The user agent MUST use an algorithm equivalent to the following algorithm to compute the "cookie-string" from a cookie store and a request-uri:"
    fn applies(&self, cookie: &crate::helpers::cookie::Cookie) -> bool {
        cookie.domain_matches(&self.host)
            && cookie.path_matches(&self.path)
            && (!cookie.secure || self.scheme == "https")
    }
}

/// Whether a cookie the client sent was ever set, and how closely.
enum PreviouslySet {
    /// Never seen set for this request's host — it may predate the capture.
    Never,
    /// Seen set for the host, but never for a path this request matches.
    ForAnotherPath,
    /// Seen set for host and path, so it was applicable once and is not now.
    AndApplicable,
}

/// Search the history for a `Set-Cookie` that would have put `name` in the
/// store for this request.
///
/// The history is walked in whatever order it comes in: `AndApplicable` ends
/// the walk wherever it is found, and `ForAnotherPath` is true of the whole
/// history or of none of it, so neither answer depends on the order.
fn previously_set(
    history: &crate::transaction_history::TransactionHistory,
    name: &str,
    request: &RequestScope,
) -> PreviouslySet {
    let mut for_another_path = false;
    for (past, resp) in history.responses() {
        for line in crate::helpers::headers::field_lines(&resp.headers, "set-cookie") {
            let Some(cookie) =
                crate::helpers::cookie::parse_set_cookie(line, &past.request.uri, past.timestamp)
            else {
                continue;
            };
            if cookie.name != name || !cookie.domain_matches(&request.host) {
                continue;
            }
            if cookie.path_matches(&request.path) {
                return PreviouslySet::AndApplicable;
            }
            for_another_path = true;
        }
    }
    if for_another_path {
        PreviouslySet::ForAnotherPath
    } else {
        PreviouslySet::Never
    }
}

impl CookieLifecycle {
    /// A cookie marked `Secure` is not sent over an insecure channel.
    ///
    /// The stored cookie is matched on name *and value*, not name alone: the
    /// `Cookie` header omits domain and path, so a name-only match would flag a
    /// legitimate non-secure cookie whenever a secure one shares its name. The
    /// stale-value check that follows catches the mismatches this misses.
    // cite(RFC 6265 § 4.1.2.5): "The Secure attribute limits the scope of the cookie to "secure" channels"
    fn secure_cookie_stayed_on_https(
        &self,
        live: &[crate::helpers::cookie::Cookie],
        request: &RequestScope,
        name: &str,
        value: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if request.scheme == "https" {
            return None;
        }
        let sent_a_secure_cookie = live.iter().any(|c| {
            c.name == name
                && c.value == value
                && c.secure
                && c.domain_matches(&request.host)
                && c.path_matches(&request.path)
        });
        if !sent_a_secure_cookie {
            return None;
        }
        Some(ctx.report_with(
            &COOKIE_SECURE_IGNORED,
            format!(
                "Secure cookie '{}' sent over insecure transport; RFC 6265 \u{a7}5.4 excludes it from the cookie-string on a scheme that is not secure",
                name
            ),
        ))
    }
}

impl RuleMeta for CookieLifecycle {
    fn id(&self) -> &'static str {
        "cookie_lifecycle"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Cookies sent by servers via the `Set-Cookie` header establish state that a client is expected to retain and present on subsequent requests. This rule reconstructs a simplistic cookie store for a given origin and verifies that outgoing requests are consistent with that store.  It flags three broad classes of client misbehaviour:\n\n* Sending cookies after they have clearly expired or been removed.\n* Continuing to send an old value after a newer cookie with the same name/domain/path has been observed.\n* Transmitting a cookie marked `Secure` over an insecure (HTTP) transport.  The rule only flags this if the actual name/value pair sent corresponds to a known secure cookie, which avoids false positives when a non‑secure cookie with the same name is used.\n\nThe check relies solely on the captured traffic for a given client+origin; if a cookie appears in a request but the linter has never seen it set in the past, the rule assumes it pre‑dates the capture and does not complain."
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// Observes client request headers only; does not examine server
    /// behavior directly (other rules cover syntax).
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_6265_5_3, RFC_6265_5_4, RFC_6265_5_1_3, RFC_6265_5_1_4]
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
                snippet: "> GET /foo HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=1; Path=/\n\n> GET /bar HTTP/1.1\n> Host: example.com\n> Cookie: id=1\n\n< HTTP/1.1 200 OK\n< Set-Cookie: id=2; Path=/\n\n> GET /baz HTTP/1.1\n> Host: example.com\n> Cookie: id=1               # old value should have been replaced",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— two cookies, two separate mistakes"),
                snippet: "> GET /login HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: sid=abc; Secure; Path=/\n< Set-Cookie: theme=dark; Path=/\n\n> GET /dashboard HTTP/1.1\n> Host: example.com\n> Cookie: sid=abc; theme=light   # a leaked Secure cookie and a stale value, reported separately",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— secure cookie over HTTP"),
                snippet: "> GET /login HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Set-Cookie: sid=123; Secure\n\n> GET /dashboard HTTP/1.1\n> Host: example.com\n> Cookie: sid=123            # insecure transport",
            },
        ]
    }
}

impl Rule for CookieLifecycle {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Only requests that carry cookies say anything about the store.
        let sent: Vec<(String, String)> =
            crate::helpers::headers::field_lines(&tx.request.headers, "cookie")
                .flat_map(crate::helpers::cookie::parse_cookie_header)
                .collect();
        if sent.is_empty() {
            return Vec::new();
        }

        let request = RequestScope::of(&tx.request.uri);
        // Already filtered to what is unexpired at this request's time.
        let live = crate::helpers::cookie::build_cookie_store(history, tx.timestamp);

        // The pair is the unit, not the request. § 4.2.1 writes the field as
        // `cookie-pair *( ";" SP cookie-pair )`, so the pairs share a line and
        // no comma separates them; each one is a cookie the user agent decided
        // to send on its own terms, and every sentence below names the cookie it
        // is about. A request carrying ten cookies of which three are stale is
        // three things for the operator to correct, so the walk states all three
        // rather than ending at the first.
        // cite(RFC 6265 § 4.2.1): "cookie-string = cookie-pair *( ";" SP cookie-pair )"
        let mut out = Vec::new();
        for (name, value) in sent {
            // Within one pair the checks stay a chain: a value that matched a
            // stored Secure cookie exactly is not also a value the store
            // replaced, and the two sentences would be one mistake described
            // twice.
            if let Some(v) = self.secure_cookie_stayed_on_https(&live, &request, &name, &value, ctx)
            {
                out.push(v);
                continue;
            }

            // The Cookie header carries no domain or path, so which stored
            // cookie a bare `name=value` pair *is* has to be decided: §5.4's
            // cookie-string ordering lists the most specific first, and that
            // ordering is borrowed here to pick the authoritative value —
            // longest path, then longest domain.
            // cite(RFC 6265 § 5.4): "Cookies with longer paths are listed before cookies with shorter paths."
            let applicable = live
                .iter()
                .filter(|c| request.applies(c) && c.name == name)
                // `min_by_key` on the reversed key keeps the *first* of
                // equally specific candidates, which is the order the store
                // was built in.
                .min_by_key(|c| std::cmp::Reverse((c.path.len(), c.domain.len())));

            if let Some(applicable) = applicable {
                if applicable.value != value {
                    out.push(ctx.report_with(
                        &COOKIE_VALUE_CONFLICTING,
                        format!(
                            "Cookie '{}' value '{}' does not match stored value '{}', likely stale",
                            name, value, applicable.value
                        ),
                    ));
                }
                continue;
            }

            // Nothing live by that name. Why not?
            match previously_set(history, &name, &request) {
                // It was live once and is not now, so the client is holding
                // a store the user agent was required to have emptied.
                // cite(RFC 6265 § 5.3): "The user agent MUST evict all expired cookies from the cookie store if, at any time, an expired cookie exists in the cookie store."
                PreviouslySet::AndApplicable => out.push(ctx.report_with(
                    &COOKIE_SCOPE_IGNORED,
                    format!(
                        "Cookie '{}' was previously set but is expired or removed and should not be sent; RFC 6265 \u{a7}5.3 has a user agent evict it from the store",
                        name
                    ),
                )),
                PreviouslySet::ForAnotherPath => out.push(ctx.report_with(
                    &COOKIE_SCOPE_IGNORED,
                    format!(
                        "Cookie '{}' is not valid for path '{}' and should not be sent; RFC 6265 \u{a7}5.4 excludes a cookie whose path does not path-match the request",
                        name, request.path
                    ),
                )),
                // The cookie may predate the capture; assume it is legitimate.
                PreviouslySet::Never => {}
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CookieLifecycle;

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
            body_interrupted: false,
            trailers: None,
        });
        if let Some(ts) = timestamp {
            tx.timestamp = ts;
        }
        tx
    }

    /// Every finding and the id it draws. All three are the *user agent's*
    /// rather than the server's, which is what makes them the first `cookie`
    /// entries about the `Cookie` field, and only the first of the three is
    /// something this proxy can be sure of.
    #[test]
    fn each_finding_names_its_entry() {
        let ts = chrono::Utc::now();
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]);
        let judge = |set_cookie: &str, set_on: &str, sent_on: &str, cookie: &str| {
            let prev = make_resp_tx(set_on, Some(set_cookie), Some(ts));
            let mut tx = make_tx_with_req(sent_on, Some(cookie));
            tx.timestamp = ts + chrono::Duration::seconds(1);
            crate::test_helpers::run_rule(
                &CookieLifecycle,
                &tx,
                &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
                &cfg,
            )
        };

        let found = judge(
            "a=1; Secure",
            "https://example.com/",
            "http://example.com/",
            "a=1",
        )
        .expect("a finding");
        assert_eq!(found.violation, "cookie_secure_ignored");

        let found = judge(
            "a=1; Path=/only",
            "https://example.com/only",
            "https://example.com/elsewhere",
            "a=1",
        )
        .expect("a finding");
        assert_eq!(found.violation, "cookie_scope_ignored");

        let found =
            judge("a=1", "https://example.com/", "https://example.com/", "a=2").expect("a finding");
        assert_eq!(found.violation, "cookie_value_conflicting");
    }

    #[test]
    fn no_violation_without_history() {
        let rule = CookieLifecycle;
        let tx = make_tx_with_req("https://example.com/", Some("foo=1"));
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        )
        .is_none());
    }

    #[test]
    fn unrelated_cookie_ignored() {
        let rule = CookieLifecycle;
        let ts = chrono::Utc::now();
        // history contains a cookie named a
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("b=2"));
        tx.timestamp = ts + chrono::Duration::seconds(1);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        )
        .is_none());
    }

    #[test]
    fn secure_cookie_over_https_ok() {
        let rule = CookieLifecycle;
        let ts = chrono::Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Secure"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn cookie_sent_within_lifetime() {
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Max-Age=60"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(30);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        )
        .is_none());
    }

    #[test]
    fn expired_cookie_sent_flagged() {
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Max-Age=1"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(5);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("expired or removed"));
    }

    #[test]
    fn stale_value_flagged() {
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev1 = make_resp_tx("https://example.com/", Some("a=1; Max-Age=60"), Some(ts));
        let prev2 = make_resp_tx(
            "https://example.com/",
            Some("a=2; Max-Age=60"),
            Some(ts + chrono::Duration::seconds(10)),
        );
        let mut tx = make_tx_with_req("https://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(20);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev2, prev1]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("value"));
    }

    #[test]
    fn secure_cookie_over_http_flagged() {
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Secure"), Some(ts));
        let mut tx = make_tx_with_req("http://example.com/", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
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
        let rule = CookieLifecycle;
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
            prev_nonsecure,
            prev_secure,
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(
            v.is_none(),
            "should not flag secure cookie if sent value is different"
        );
    }

    #[test]
    fn path_mismatch_flagged() {
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/private"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn path_prefix_boundary_flagged() {
        // /foo should not match /foobar
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/foo"), Some(ts));
        let mut tx = make_tx_with_req("https://example.com/foobar", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid for path"));
    }

    #[test]
    fn host_only_cookie_to_subdomain_not_stale_fp() {
        // Regression: a host-only cookie (no Domain attribute) set on
        // example.com must not be treated as applicable to sub.example.com.
        // A different value carried to the subdomain is another host's cookie,
        // not a stale one, so the rule must stay silent (RFC 6265 §5.4).
        let rule = CookieLifecycle;
        let ts = Utc::now();
        let prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        let mut tx = make_tx_with_req("https://sub.example.com/", Some("a=2"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
            )
            .is_none(),
            "host-only cookie must not be seen as applicable to a subdomain"
        );
    }

    #[test]
    fn domain_mismatch_ignored() {
        let rule = CookieLifecycle;
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
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        // request to other.com should not be influenced by cookie from example.com
        assert!(
            v.is_none(),
            "cookie from different domain should be ignored"
        );
    }

    /// Three pairs on one `Cookie` line, each defective in a different way, and
    /// each drawing its own entry. `cookie-string = cookie-pair *( ";" SP
    /// cookie-pair )` puts them on one line with no comma between them, so a
    /// reading that ends at the first pair it has something to say about tells
    /// an operator to fix one of three cookies and stay silent about the rest.
    #[test]
    fn every_defective_pair_is_reported() {
        let ts = Utc::now();
        let mut prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Secure; Path=/"),
            Some(ts),
        );
        for extra in ["b=1; Path=/", "c=1; Path=/private"] {
            prev.response.as_mut().unwrap().headers.append(
                "set-cookie",
                hyper::header::HeaderValue::from_str(extra).unwrap(),
            );
        }
        let mut tx = make_tx_with_req("http://example.com/public", Some("a=1; b=2; c=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let found = crate::test_helpers::run_rule_all(
            &CookieLifecycle,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "cookie_secure_ignored",
                "cookie_value_conflicting",
                "cookie_scope_ignored"
            ],
            "one finding per defective pair, in the order the pairs were sent"
        );
        // Each names the cookie it is about, which is what makes the pair the
        // unit rather than the request.
        assert!(found[0].message.contains("'a'"));
        assert!(found[1].message.contains("'b'"));
        assert!(found[2].message.contains("'c'"));
    }

    /// The other direction: pairs the store agrees with are walked past rather
    /// than ending the reading, so a defective pair behind two sound ones is
    /// still reported.
    #[test]
    fn sound_pairs_do_not_end_the_walk() {
        let ts = Utc::now();
        let mut prev = make_resp_tx("https://example.com/", Some("a=1; Path=/"), Some(ts));
        prev.response.as_mut().unwrap().headers.append(
            "set-cookie",
            hyper::header::HeaderValue::from_str("b=1; Path=/").unwrap(),
        );
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1; b=1; c=9"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]);
        // `c` was never set at all, so it may predate the capture and is not a
        // finding; nothing is reported.
        assert!(crate::test_helpers::run_rule_all(
            &CookieLifecycle,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        )
        .is_empty());

        // Same two sound pairs, and a third the store says was replaced.
        let mut tx = make_tx_with_req("https://example.com/public", Some("a=1; b=2"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let found = crate::test_helpers::run_rule_all(
            &CookieLifecycle,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].violation, "cookie_value_conflicting");
        assert!(found[0].message.contains("'b'"));
    }

    /// One pair states one thing. `a=1` matches a stored `Secure` cookie
    /// exactly, and a *different* non-secure `a` is what the store would
    /// otherwise offer for this path — so both checks have something to say and
    /// the pair still draws one finding. The checks within a pair stay a chain;
    /// only the walk across pairs was ever the masking.
    #[test]
    fn one_pair_draws_one_finding() {
        let ts = Utc::now();
        let mut prev = make_resp_tx(
            "https://example.com/",
            Some("a=1; Secure; Path=/"),
            Some(ts),
        );
        prev.response.as_mut().unwrap().headers.append(
            "set-cookie",
            hyper::header::HeaderValue::from_str("a=2; Path=/public").unwrap(),
        );
        let mut tx = make_tx_with_req("http://example.com/public", Some("a=1"));
        tx.timestamp = ts + chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let found = crate::test_helpers::run_rule_all(
            &CookieLifecycle,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_lifecycle"]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].violation, "cookie_secure_ignored");
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cookie_lifecycle");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
