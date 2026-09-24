// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::vary::{RFC_9110_12_5_5, VARY_ACCEPT_ENCODING_MISSING};
use crate::violations::ViolationDef;

/// One entry: a coded response whose `Vary` leaves out the field it was coded
/// from.
static DECLARED: &[&ViolationDef] = &[&VARY_ACCEPT_ENCODING_MISSING];

/// A cacheable response to a `GET` that carried `Accept-Encoding`, whose
/// content is coded, and whose `Vary` names neither `Accept-Encoding` nor `*`.
pub struct VaryAndContentEncodingConsistent;

/// RFC 9111, for what a cache does with a response whose `Vary` leaves a
/// selecting field out.
const RFC_9111_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Calculating Cache Keys with the Vary Header Field — a cache matches a later request only on the fields the stored response nominated, so a field left out is one a cache never compares",
};

impl RuleMeta for VaryAndContentEncodingConsistent {
    fn id(&self) -> &'static str {
        "vary_and_content_encoding_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("A response coded from Accept-Encoding names it in Vary")
    }

    fn description(&self) -> &'static str {
        "Reports a cacheable response whose content coding was chosen from the request's `Accept-Encoding` and whose `Vary` does not name that field.\n\n**The coding is the selection, and the response says so.** A server answering `Accept-Encoding: gzip, br` with `Content-Encoding: br` has tailored the content to a preference the request expressed — the case RFC 9110 §12.5.5 has in mind when it says an origin *\"SHOULD generate a Vary header field on a cacheable response when it wishes that response to be selectively reused\"*. Without it, a cache compares nothing about the next request's `Accept-Encoding` (RFC 9111 §4.1) and hands the `br` body to a client that cannot decode it.\n\n**When it is not reported.** The SHOULD is conditional, and each condition the wire shows is read:\n\n- the response has to be one a cache could keep at all (RFC 9111 §3) — a `GET`, a final status, no `no-store`, and some licence to store it;\n- the request has to have carried a non-empty `Accept-Encoding`: a request without one accepts any coding (§12.5.3), so a coded answer to it selected nothing;\n- the response must not already limit reuse. §12.5.5 lets `Vary` be elided *\"particularly when reuse is already limited by cache response directives\"*, so an unqualified `no-cache`, a `private`, or a `max-age=0` with no `s-maxage` is the origin having made that choice.\n\n`Vary: *` satisfies it — no cache reuses such a response under any coding — and so does `Accept-Encoding` on any `Vary` field line, in any case.\n\n**Not this rule's.** Whether the coding is registered, or one the request accepted, is `content_encoding_registered`'s; a coded response whose earlier sibling for the same resource shared its strong `ETag` is `etag_and_content_encoding_consistent`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_12_5_5, RFC_9111_4_1]
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
                label: None,
                snippet: "GET /app.js HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, br\n\nHTTP/1.1 200 OK\nContent-Encoding: br\nVary: Accept-Encoding\nCache-Control: max-age=3600\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— reuse already limited by the response's own directives"),
                snippet: "GET /app.js HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, br\n\nHTTP/1.1 200 OK\nContent-Encoding: br\nCache-Control: private, max-age=3600\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /app.js HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, br\n\nHTTP/1.1 200 OK\nContent-Encoding: br\nCache-Control: public, max-age=3600\n",
            },
        ]
    }
}

/// Whether the response's own directives already limit its reuse, which is the
/// case § 12.5.5 names for leaving `Vary` out.
///
/// Three readings, each a cache being told something that makes a selecting
/// field matter to nobody but the requester: an unqualified `no-cache` has every
/// reuse go back to the origin, `private` keeps the response in one user
/// agent's cache, and a `max-age=0` with no `s-maxage` makes it stale on
/// arrival. A `max-age=0` beside a positive `s-maxage` is a response a shared
/// cache reuses for that long, so it is not read as limited.
// cite(RFC 9111 § 5.2.2.4): "The no-cache response directive, in its unqualified form (without an argument), indicates that the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
// cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
fn reuse_already_limited(headers: &hyper::HeaderMap) -> bool {
    use crate::helpers::cache_control::{delta_seconds, has_unqualified};
    has_unqualified(headers, "no-cache")
        || has_unqualified(headers, "private")
        || (delta_seconds(headers, "max-age") == Some(0)
            && delta_seconds(headers, "s-maxage").is_none_or(|s| s == 0))
}

impl Rule for VaryAndContentEncodingConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        // A `HEAD` answer may omit `Vary` by name (RFC 9110 § 9.3.2's own
        // example), so the pairing is read on `GET` alone.
        // cite(RFC 9110 § 9.3.2): "Such a response to GET might contain Content-Length and Vary fields, for example, that are not generated within a HEAD response."
        if tx.request.method != "GET"
            || !crate::helpers::stored_response::response_is_storable(
                &tx.request.method,
                &tx.request.headers,
                resp.status,
                &resp.headers,
            )
            || reuse_already_limited(&resp.headers)
        {
            return Vec::new();
        }

        // A request with no `Accept-Encoding` accepts any coding, so a coded
        // answer to it was not selected from a preference; an empty one asks for
        // none, and a coded answer to it is a different defect.
        // cite(RFC 9110 § 12.5.3): "If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent."
        let asked = crate::helpers::headers::combined_field_value_as_written(
            &tx.request.headers,
            "accept-encoding",
        );
        let Some(asked) = asked.filter(|v| !crate::helpers::headers::trim_ows(v).is_empty()) else {
            return Vec::new();
        };

        let codings = crate::helpers::content_coding::applied_codings(&resp.headers);
        if codings.is_empty() {
            return Vec::new();
        }

        // `*` fails every match, so it keeps the coded response from any request
        // just as well as naming the field does.
        // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
        if crate::helpers::vary::vary_nomination(&resp.headers).nominates("accept-encoding") {
            return Vec::new();
        }

        vec![ctx.report_with(
            &VARY_ACCEPT_ENCODING_MISSING,
            format!(
                "Content-Encoding: {} answers Accept-Encoding: {} on a cacheable response whose \
                 Vary does not name Accept-Encoding \u{2014} a cache can hand this coded body \
                 to a request that does not accept it; add Accept-Encoding to Vary \
                 (RFC 9110 \u{a7} 12.5.5)",
                crate::helpers::shown::shown_in_finding(&codings.join(", ")),
                crate::helpers::shown::shown_in_finding(crate::helpers::headers::trim_ows(&asked)),
            ),
        )]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryAndContentEncodingConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(
        method: &str,
        request: &[(&str, &str)],
        status: u16,
        response: &[(&str, &str)],
    ) -> Vec<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, response);
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(request);
        crate::test_helpers::run_rule_all(
            &VaryAndContentEncodingConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "vary_and_content_encoding_consistent",
            ]),
        )
    }

    const ASKS: &[(&str, &str)] = &[("accept-encoding", "gzip, br")];

    /// The `Vary` values that name the field, and the ones that do not.
    #[rstest]
    #[case::absent(None, true)]
    #[case::other_field(Some("Accept-Language"), true)]
    #[case::empty(Some(""), true)]
    #[case::named(Some("Accept-Encoding"), false)]
    #[case::lowercase(Some("accept-encoding"), false)]
    #[case::among_others(Some("Origin, Accept-Encoding"), false)]
    #[case::wildcard(Some("*"), false)]
    fn a_coded_response_names_accept_encoding(#[case] vary: Option<&str>, #[case] reported: bool) {
        let mut response = vec![("content-encoding", "br"), ("cache-control", "max-age=60")];
        if let Some(v) = vary {
            response.push(("vary", v));
        }
        let found = judge("GET", ASKS, 200, &response);
        assert_eq!(found.len(), usize::from(reported), "{found:?}");
        if reported {
            assert_eq!(found[0].violation, "vary_accept_encoding_missing");
            assert_eq!(found[0].severity, crate::lint::Severity::Warn);
            assert!(
                found[0].message.contains("Content-Encoding: br"),
                "{}",
                found[0].message
            );
            assert!(
                found[0].message.contains("Accept-Encoding: gzip, br"),
                "{}",
                found[0].message
            );
        }
    }

    /// A `Vary` on a second field line is the same field.
    #[test]
    fn a_second_vary_line_is_read() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-encoding", "gzip"), ("vary", "Origin")],
        );
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("vary", "Accept-Encoding".parse().unwrap());
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(ASKS);
        let found = crate::test_helpers::run_rule_all(
            &VaryAndContentEncodingConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "vary_and_content_encoding_consistent",
            ]),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// Each condition the SHOULD rests on, turned off one at a time.
    #[rstest]
    #[case::unencoded("GET", ASKS, 200, &[("cache-control", "max-age=60")])]
    #[case::identity("GET", ASKS, 200, &[("content-encoding", "identity"), ("cache-control", "max-age=60")])]
    #[case::nothing_asked("GET", &[], 200, &[("content-encoding", "gzip"), ("cache-control", "max-age=60")])]
    #[case::empty_ask("GET", &[("accept-encoding", "")], 200, &[("content-encoding", "gzip"), ("cache-control", "max-age=60")])]
    #[case::head("HEAD", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "max-age=60")])]
    #[case::post("POST", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "max-age=60")])]
    #[case::no_store("GET", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "no-store")])]
    #[case::not_storable_status("GET", ASKS, 403, &[("content-encoding", "gzip")])]
    #[case::no_cache("GET", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "no-cache")])]
    #[case::private("GET", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "private, max-age=900")])]
    #[case::max_age_zero("GET", ASKS, 200, &[("content-encoding", "gzip"), ("cache-control", "public, max-age=0, must-revalidate")])]
    fn outside_the_should_nothing_is_reported(
        #[case] method: &str,
        #[case] request: &[(&str, &str)],
        #[case] status: u16,
        #[case] response: &[(&str, &str)],
    ) {
        let found = judge(method, request, status, response);
        assert!(found.is_empty(), "{found:?}");
    }

    /// The limits that do not limit a shared cache are not read as limits.
    #[rstest]
    #[case::heuristic(&[("content-encoding", "gzip")])]
    #[case::qualified_no_cache(&[("content-encoding", "gzip"), ("cache-control", "no-cache=\"Set-Cookie\", max-age=60")])]
    #[case::qualified_private(&[("content-encoding", "gzip"), ("cache-control", "private=\"Set-Cookie\", max-age=60")])]
    #[case::shared_lifetime(&[("content-encoding", "gzip"), ("cache-control", "max-age=0, s-maxage=600")])]
    fn a_response_a_shared_cache_reuses_is_reported(#[case] response: &[(&str, &str)]) {
        let found = judge("GET", ASKS, 200, response);
        assert_eq!(found.len(), 1, "{found:?}");
    }
}
