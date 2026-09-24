// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::vary::{FETCH_CORS_HTTP_CACHES, VARY_ORIGIN_MISSING};
use crate::violations::ViolationDef;

/// One entry: an `Access-Control-Allow-Origin` that follows the `Origin`, on a
/// response whose `Vary` does not name it.
static DECLARED: &[&ViolationDef] = &[&VARY_ORIGIN_MISSING];

/// Compares each cacheable response's `Access-Control-Allow-Origin` with the
/// earlier ones for the same resource, and where the value has been seen to
/// follow the request's `Origin`, reports a response whose `Vary` does not name
/// `Origin`.
pub struct VaryAndCorsConsistent;

impl RuleMeta for VaryAndCorsConsistent {
    fn id(&self) -> &'static str {
        "vary_and_cors_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("A CORS grant chosen from the Origin is keyed on it")
    }

    fn description(&self) -> &'static str {
        "Reports a cacheable response without `Origin` in its `Vary`, for a resource whose `Access-Control-Allow-Origin` has been seen to change with the request's `Origin`.\n\n**Fetch describes the failure step by step** in its background note on CORS and HTTP caches. A server that sends `Access-Control-Allow-Origin` only in answer to a CORS request sends a response without it to a navigation; the browser caches that, and answers the next CORS request for the resource from the cache, without the header, so the request fails. A server that echoes the `Origin` it was sent has the same problem between two origins: a cache hands the second origin the first one's grant. *\"If CORS protocol requirements are more complicated than setting `Access-Control-Allow-Origin` to * or a static origin, `Vary` is to be used.\"*\n\n**The evidence is two responses, never one.** A value equal to the request's `Origin` is also what a static single-origin configuration sends whenever that origin is the one asking, and Fetch says a static origin needs no `Vary`. What shows the value is computed is two responses for the resource that answer requests with different `Origin` values (one of them may send no `Origin`) and carry different `Access-Control-Allow-Origin` values (one of them may send none). Both must be `GET` answers of the same status that a cache could have stored (RFC 9111 §3), from the same client for the same target URI: a `404` without CORS headers beside a `200` with them is two states of the resource rather than a selection.\n\n**Every response of such a resource owes it**, the non-CORS ones included: the cached response Fetch's example goes wrong with is the one to a navigation. `Vary: *` satisfies it.\n\n**Not this rule's.** Whether `Access-Control-Allow-Origin` is well formed, or agrees with `Access-Control-Allow-Credentials`, belongs to the CORS header rules; a preflight (`OPTIONS`) response is not cached by HTTP caches at all."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[FETCH_CORS_HTTP_CACHES]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the grant follows the Origin, and Vary says so"),
                snippet: "GET /data HTTP/1.1\nHost: api.example.com\n\nHTTP/1.1 200 OK\nVary: Origin\nCache-Control: max-age=600\n\nGET /data HTTP/1.1\nHost: api.example.com\nOrigin: https://app.example.com\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://app.example.com\nVary: Origin\nCache-Control: max-age=600\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a static grant, sent to every request"),
                snippet: "GET /data HTTP/1.1\nHost: api.example.com\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nCache-Control: max-age=600\n\nGET /data HTTP/1.1\nHost: api.example.com\nOrigin: https://app.example.com\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nCache-Control: max-age=600\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the grant sent only to a CORS request"),
                snippet: "GET /data HTTP/1.1\nHost: api.example.com\n\nHTTP/1.1 200 OK\nCache-Control: max-age=600\n\nGET /data HTTP/1.1\nHost: api.example.com\nOrigin: https://app.example.com\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://app.example.com\nCache-Control: max-age=600\n",
            },
        ]
    }
}

/// What one exchange says about the pairing, if it is one this rule compares:
/// the request's `Origin` and the response's `Access-Control-Allow-Origin`, as
/// written and trimmed, each `None` where the message carried none.
///
/// A `GET` answer a cache could have stored, because the failure is a cache's.
/// Both fields are singletons, so the first line is the value.
fn grant(
    tx: &crate::http_transaction::HttpTransaction,
) -> Option<(Option<String>, Option<String>)> {
    let resp = tx.response.as_ref()?;
    if tx.request.method != "GET"
        || !crate::helpers::stored_response::response_is_storable(
            &tx.request.method,
            &tx.request.headers,
            resp.status,
            &resp.headers,
        )
    {
        return None;
    }
    let first = |headers: &hyper::HeaderMap, name: &str| {
        crate::helpers::headers::field_lines_as_written(headers, name)
            .into_iter()
            .next()
            .map(|line| crate::helpers::headers::trim_ows(&line).to_string())
    };
    Some((
        first(&tx.request.headers, "origin"),
        first(&resp.headers, "access-control-allow-origin"),
    ))
}

/// How a finding names a value that may be absent.
fn shown(value: Option<&str>) -> String {
    value.map_or_else(
        || "none".to_string(),
        |v| format!("'{}'", crate::helpers::shown::shown_in_finding(v)),
    )
}

impl Rule for VaryAndCorsConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        let Some((origin, allowed)) = grant(tx) else {
            return Vec::new();
        };
        // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
        if crate::helpers::vary::vary_nomination(&resp.headers).nominates("origin") {
            return Vec::new();
        }

        // The newest earlier answer of the same status whose request carried a
        // different `Origin` and whose response a different grant. Either may be
        // absent on either side: Fetch's own example is the non-CORS request
        // answered without the header.
        // cite(Fetch): "consider what happens if `Vary` is not used and a server is configured to send `Access-Control-Allow-Origin` for a certain resource only in response to a CORS request."
        let Some((their_origin, their_allowed)) = history
            .iter()
            .filter(|e| e.response.as_ref().is_some_and(|r| r.status == resp.status))
            .filter_map(grant)
            .find(|(o, a)| *o != origin && *a != allowed)
        else {
            return Vec::new();
        };

        vec![ctx.report_with(
            &VARY_ORIGIN_MISSING,
            format!(
                "Access-Control-Allow-Origin {} answers Origin {} here, and an earlier {} for \
                 the same URI answered Origin {} with {} \u{2014} the grant follows the \
                 request's Origin, so a cache without Origin in Vary hands one origin's answer \
                 to another; add Origin to this response's Vary (Fetch, CORS protocol and \
                 HTTP caches)",
                shown(allowed.as_deref()),
                shown(origin.as_deref()),
                resp.status,
                shown(their_origin.as_deref()),
                shown(their_allowed.as_deref()),
            ),
        )]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryAndCorsConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    type Exchange<'a> = (&'a [(&'a str, &'a str)], u16, &'a [(&'a str, &'a str)]);

    /// A sequence of `GET`s for one resource, oldest first; the last is judged.
    fn judge(exchanges: &[Exchange<'_>]) -> Vec<Violation> {
        let base = chrono::Utc::now();
        let n = exchanges.len() as i64;
        let mut txs: Vec<_> = exchanges
            .iter()
            .enumerate()
            .map(|(i, (request, status, response))| {
                let mut t =
                    crate::test_helpers::make_test_transaction_with_response(*status, response);
                t.request.uri = "http://example/data".to_string();
                t.request.headers = crate::test_helpers::make_headers_from_pairs(request);
                t.timestamp = base - chrono::Duration::seconds(n - i as i64);
                t
            })
            .collect();
        let tx = txs.pop().expect("an exchange to judge");
        txs.reverse();
        crate::test_helpers::run_rule_all(
            &VaryAndCorsConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(txs),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "vary_and_cors_consistent",
            ]),
        )
    }

    const NO_ORIGIN: &[(&str, &str)] = &[];
    const APP: &[(&str, &str)] = &[("origin", "https://app.example")];
    const OTHER: &[(&str, &str)] = &[("origin", "https://other.example")];
    const NO_GRANT: &[(&str, &str)] = &[("cache-control", "max-age=600")];
    const APP_GRANT: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "https://app.example"),
    ];
    const OTHER_GRANT: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "https://other.example"),
    ];
    const STAR: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "*"),
    ];
    const APP_GRANT_VARIED: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "https://app.example"),
        ("vary", "Accept-Encoding, origin"),
    ];
    const APP_GRANT_WILDCARD: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "https://app.example"),
        ("vary", "*"),
    ];
    const APP_GRANT_404: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("access-control-allow-origin", "https://app.example"),
    ];
    const APP_GRANT_NO_STORE: &[(&str, &str)] = &[
        ("cache-control", "no-store"),
        ("access-control-allow-origin", "https://app.example"),
    ];

    /// Fetch's example, in both orders, and the echo between two origins.
    #[rstest]
    #[case::navigation_first(&[(NO_ORIGIN, 200, NO_GRANT), (APP, 200, APP_GRANT)])]
    #[case::navigation_second(&[(APP, 200, APP_GRANT), (NO_ORIGIN, 200, NO_GRANT)])]
    #[case::two_origins_echoed(&[(APP, 200, APP_GRANT), (OTHER, 200, OTHER_GRANT)])]
    #[case::star_then_echo(&[(NO_ORIGIN, 200, STAR), (APP, 200, APP_GRANT)])]
    fn a_grant_that_follows_the_origin_is_keyed_on_it(#[case] exchanges: &[Exchange<'_>]) {
        let found = judge(exchanges);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].violation, "vary_origin_missing");
        assert_eq!(found[0].severity, crate::lint::Severity::Warn);
    }

    /// The finding names both pairs, so an operator can see the grant move.
    #[test]
    fn the_finding_names_both_origins_and_both_grants() {
        let found = judge(&[(NO_ORIGIN, 200, NO_GRANT), (APP, 200, APP_GRANT)]);
        let msg = &found[0].message;
        assert!(
            msg.contains("Access-Control-Allow-Origin 'https://app.example' answers Origin 'https://app.example'"),
            "{msg}"
        );
        assert!(msg.contains("answered Origin none with none"), "{msg}");
    }

    /// Silence where the grant did not move, did not move with the `Origin`, or
    /// the response is already keyed or never stored.
    #[rstest]
    #[case::static_star(&[(NO_ORIGIN, 200, STAR), (APP, 200, STAR)])]
    #[case::static_origin(&[(OTHER, 200, APP_GRANT), (APP, 200, APP_GRANT)])]
    #[case::same_origin_twice(&[(APP, 200, NO_GRANT), (APP, 200, APP_GRANT)])]
    #[case::varied(&[(NO_ORIGIN, 200, NO_GRANT), (APP, 200, APP_GRANT_VARIED)])]
    #[case::wildcard(&[(NO_ORIGIN, 200, NO_GRANT), (APP, 200, APP_GRANT_WILDCARD)])]
    #[case::other_status(&[(NO_ORIGIN, 404, NO_GRANT), (APP, 200, APP_GRANT_404)])]
    #[case::not_storable(&[(NO_ORIGIN, 200, NO_GRANT), (APP, 200, APP_GRANT_NO_STORE)])]
    #[case::alone(&[(APP, 200, APP_GRANT)])]
    fn a_grant_that_does_not_follow_the_origin_is_silence(#[case] exchanges: &[Exchange<'_>]) {
        let found = judge(exchanges);
        assert!(found.is_empty(), "{found:?}");
    }
}
