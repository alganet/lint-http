// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::access_control_allow_origin::{
    ACCESS_CONTROL_ALLOW_ORIGIN_CONFLICTING, ACCESS_CONTROL_ALLOW_ORIGIN_CREDENTIALS_CONFLICTING,
    ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED, FETCH_3_3_3, FETCH_4_10,
};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::origin::{
    origin_defect, ORIGIN_MALFORMED, ORIGIN_PATH_FORBIDDEN, RFC_6454_7_1,
};
use crate::violations::uri::{
    RFC_3986_2, RFC_3986_3_1, URI_CHARACTER_FORBIDDEN, URI_SCHEME_CHARACTER_FORBIDDEN,
    URI_SCHEME_EMPTY, URI_SCHEME_LEADING_LETTER_MISSING,
};
use crate::violations::ViolationDef;

/// Ten, across four subjects, and the spread is the rule's subject matter: it
/// reads an `Origin` and an `Access-Control-Allow-Origin` and asks whether they
/// agree.
///
/// The two productions an `Origin` borrows are RFC 3986's — a scheme name, and
/// the alphabet a URI is composed from — and the two verdicts left over are the
/// field's own, on the `origin` subject that now holds them: a path where the
/// production has no path component, and a value deriving from neither
/// alternative. The response field's three are what the CORS check refuses,
/// and the repeated field line is § 5.3's wherever it happens.
static DECLARED: &[&ViolationDef] = &[
    &URI_SCHEME_EMPTY,
    &URI_SCHEME_LEADING_LETTER_MISSING,
    &URI_SCHEME_CHARACTER_FORBIDDEN,
    &URI_CHARACTER_FORBIDDEN,
    &FIELD_LINE_DUPLICATED,
    &ORIGIN_PATH_FORBIDDEN,
    &ORIGIN_MALFORMED,
    &ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED,
    &ACCESS_CONTROL_ALLOW_ORIGIN_CONFLICTING,
    &ACCESS_CONTROL_ALLOW_ORIGIN_CREDENTIALS_CONFLICTING,
];

pub struct OriginMatchingForCors;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6454: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6454",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc6454.html",
    note: "The Web Origin Concept",
};
/// The serializer § 4.10's left-hand side runs, and the one step of it that
/// makes a serialization differ from a `serialized-origin` a sender wrote.
const RFC_6454_6_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6454",
    section: Some("6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-6.2",
    note: "ASCII Serialization of an Origin — the algorithm the CORS check compares its left-hand side against, whose port step is conditional on the port differing from the scheme's default",
};
const MDN_ACCESS_CONTROL_ALLOW_ORIGIN: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Access-Control-Allow-Origin",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin",
    note: "Access-Control-Allow-Origin",
};

impl RuleMeta for OriginMatchingForCors {
    fn id(&self) -> &'static str {
        "origin_matching_for_cors"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Origin Matching for CORS Responses")
    }

    fn description(&self) -> &'static str {
        "When a server responds to a cross-origin request the `Access-Control-Allow-Origin`\nheader must either repeat the origin that asked or use the wildcard `*`.\nThe wildcard shares only with a request that carries no credentials, so beside\n`Access-Control-Allow-Credentials: true` it leaves that `true` turning nothing on.\n\nThis rule looks at transactions where the client supplied an `Origin` header\nand the server returned an `Access-Control-Allow-Origin` header.  It\nvalidates that the header set is semantically consistent with the request\norigin and reports a `*` beside a credentials `true`.  If the request's\n`Origin` value is syntactically invalid the rule also raises a violation.\n\n**The comparison is asymmetric, because Fetch §4.10 names two different things on its two sides.** The check compares *the result of byte-serializing the request's origin* against the response field's value as it arrived. The left-hand side is an algorithm run over an origin triple — RFC 6454 §6.2, whose port step is conditional on the port differing from the scheme's default, over a triple §4 has already lower-cased — and the right-hand side is not normalised at all. So the request's `Origin` is serialized before it is compared and the response's value is not, and the two directions are genuinely different findings: `Origin: https://a.example:443` answered with `Access-Control-Allow-Origin: https://a.example` is *correct* and draws nothing, because 443 is the `https` default port and no user agent would have serialized it; the same pair the other way round — a canonical `Origin` answered by a value that writes the port out — fails the check in every user agent and is reported.\n\nThis check applies to server responses."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6454,
            RFC_6454_7_1,
            RFC_6454_6_2,
            FETCH_3_3_3,
            FETCH_4_10,
            MDN_ACCESS_CONTROL_ALLOW_ORIGIN,
            RFC_3986_2,
            RFC_3986_3_1,
            RFC_9110_5_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **This rule reads a field from each peer, so it answers one finding at
    /// a time.** The `Origin` it validates first is the request's, written by
    /// the client; every finding after it is about the
    /// `Access-Control-Allow-Origin` the origin server sent back. One
    /// presumption would have been wrong for one side or the other.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(exact echo)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.org",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(wildcard, no credentials)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`*` with credentials)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(mismatched origin)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://foo.example\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://bar.example",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the scheme's default port is not in the serialization the check compares)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org:443\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.org",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the response writes a port the serialization does not, so the check fails)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.org:443",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields or list)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a, https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields or list)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nOrigin: https://example.org\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a\nAccess-Control-Allow-Origin: https://b",
            },
        ]
    }
}

impl Rule for OriginMatchingForCors {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let req = &tx.request;
            let headers = &req.headers;

            // Nothing to do if request did not include Origin header. The line is
            // read as the octets the sender wrote: `Origin` is `null` or a
            // serialized origin, both inside visible US-ASCII, so a value the
            // string reader refuses is a value the syntax check below refuses —
            // and refusing it here first meant the rule said nothing at all.
            let origin_line = crate::helpers::headers::field_lines_as_written(headers, "origin")
                .into_iter()
                .next()?;
            let origin = crate::helpers::headers::trim_ows(&origin_line);

            // Validate origin syntax using shared helper (handles "null" and
            // serialized origins). Two of its four verdicts are productions the
            // catalogue names — the scheme and the URI alphabet — and two are
            // this field's own: a path where the production has no component for
            // one, and a value deriving from neither alternative.
            //
            // **This `return` ends the reading of the response, and that is a
            // decline rather than a slip.** One finding about the client's
            // `Origin` stands in front of four the response could have earned,
            // and they are attributed to the other peer — so `--about server`
            // shows nothing about this exchange. What makes it safe is not the
            // shape of the body; it is that every one of the four is said
            // somewhere else, and
            // [`Self::the_response_side_findings_this_decline_rests_on_are_declared_elsewhere`]
            // asserts each of those declarations by name so the day one of them
            // moves, this silence becomes visible instead of staying quiet:
            //
            // - `field_line_duplicated` and `access_control_allow_origin_
            //   malformed` are `access_control_allow_origin_valid`'s, which
            //   counts the lines and reads the value whatever the request said —
            //   and says more about each than this rule does;
            // - `access_control_allow_origin_credentials_conflicting`'s *fact*
            //   is `access_control_allow_credentials_when_origin`'s
            //   `access_control_allow_credentials_conflicting`, which scans the
            //   origin field for a `*` and never reads the request;
            // - `access_control_allow_origin_conflicting` has no second declarer
            //   and needs none here, because it cannot be computed: the check
            //   compares against the *serialization* of the request's origin,
            //   and a value deriving from neither alternative of
            //   `origin-list-or-null` has none. Reported past this point it
            //   would be a comparison against a string no user agent would ever
            //   produce.
            if let Err(defect) = crate::helpers::origin::validate_origin_value(origin) {
                let message = format!(
                    "Invalid Origin header value '{}': {}",
                    crate::helpers::shown::shown_in_finding(origin),
                    defect.message()
                );
                return Some(ctx.by_client().report_with(origin_defect(defect), message));
            }

            let resp = tx.response.as_ref()?;

            // Check for Access-Control-Allow-Origin header in response. Read as
            // written for the same reason as the request's `Origin`: this rule
            // compares the two byte for byte, so a value it cannot read is a
            // value that does not match, which the finding at the end says.
            let acao_values = crate::helpers::headers::field_lines_as_written(
                &resp.headers,
                "access-control-allow-origin",
            );
            if acao_values.is_empty() {
                return None;
            }

            // Multiple header fields are not permitted; treat as violation early
            // cite(Fetch § 3.3.3): "Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response."
            if acao_values.len() > 1 {
                return Some(ctx.by_server().report_with(&FIELD_LINE_DUPLICATED, "Multiple Access-Control-Allow-Origin header fields present; only a single value is allowed".into()));
            }

            // Now we have exactly one header field; validate its value semantics
            let acao_raw = crate::helpers::headers::trim_ows(&acao_values[0]);
            // Must be a single value (not a comma-separated list)
            let members: Vec<String> = crate::helpers::list::list_members(acao_raw)
                .map(|m| m.to_string())
                .collect();
            // A field written with no value yields no members, and `!= 1` used
            // to answer that with the entry written for the opposite case. The
            // malformity entry's own definition opens "A value on the line, and
            // it derives from none of the three alternatives" — an empty field
            // puts no value on the line — and the sentence below says the field
            // "must be a single value", which is untrue of a value that is not
            // there at all: nothing here is multiple.
            //
            // What the empty field is, is `access_control_allow_origin_empty`,
            // and this rule is not the one that says so. It reads the pair, and
            // an absent value gives it nothing to compare the request's `Origin`
            // against; the field's own grammar rule declares that entry and
            // already reports it. So this declines rather than renaming the
            // finding, which would be the same defect drawn twice.
            if members.is_empty() {
                return None;
            }
            if members.len() != 1 {
                // Not a list defect: the field has no list form for a comma to
                // break, so what a second member produces is a value the CORS
                // check matches against no origin — the same thing
                // `example.com` produces, and the same entry.
                return Some(ctx.by_server().report_with(
                    &ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED,
                    "Access-Control-Allow-Origin must be a single value".into(),
                ));
            }

            let acao_val = members.into_iter().next().unwrap();
            let acao_val = crate::helpers::headers::trim_ows(&acao_val).to_string();

            // `*` shares only with a request that carries no credentials. The CORS
            // check short-circuits on `*` *only* for a request whose credentials
            // mode is not "include"; a credentialed one falls through to the
            // byte-serialized comparison below, which `*` can never satisfy.
            //
            // So the wildcard is what stands in front of credentialed sharing only
            // when the credentials field turns it on, and only the byte sequence
            // `true` does: the check compares it as bytes. `TRUE` beside `*` is a
            // response that shares with nobody's credentials whatever the origin
            // field says, and the value's own defect is
            // `access_control_allow_credentials_invalid`. **This comparison used
            // to be case-insensitive**, which named the wildcard as the obstacle
            // in a response where echoing the origin would share nothing either.
            // cite(Fetch § 4.10): "If request’s credentials mode is not "include" and origin is `*`, then return success."
            //
            // The credentials field is *got*, every line joined with ", ", so
            // two `true` lines are `true, true` and turn nothing on either.
            // cite(Fetch § 4.10, label: CORS check reads the field): "Let credentials be the result of getting `Access-Control-Allow-Credentials` from response’s header list."
            if acao_val == "*" {
                let cred = crate::helpers::headers::field_lines_as_written(
                    &resp.headers,
                    "access-control-allow-credentials",
                )
                .join(", ");
                if crate::helpers::headers::trim_ows(&cred) == "true" {
                    return Some(
                        ctx.by_server()
                            .report(&ACCESS_CONTROL_ALLOW_ORIGIN_CREDENTIALS_CONFLICTING),
                    );
                }
                return None;
            }

            // For any other value, the comparison is byte-for-byte and it is
            // **asymmetric**, because the sentence below names two different
            // things on its two sides: on the left, the *result of
            // byte-serializing the request's origin* — an algorithm run over an
            // origin triple — and on the right, `origin`, which is the response
            // field's value as it arrived.
            //
            // So the request side is serialized and the response side is not.
            // The `Origin` field text is only what a client *wrote*, and RFC
            // 6454's serializer would not write every string its grammar admits:
            // `https://a.example:443` derives from `serialized-origin` and is
            // never produced, because § 6.2's port step is conditional on the
            // port differing from the scheme's default, and § 4 has the scheme
            // and host lower-cased before the triple exists. Comparing that text
            // against the response's value reported a conflict on exactly the
            // requests a browser shares the response with: the two default
            // ports written out, and an upper-case scheme or host.
            //
            // **The reasoning that licensed the byte compare was about the other
            // alternative.** It said no case normalisation applies because
            // byte-serializing an *opaque* origin yields the lowercase literal
            // `null` — true, and about the one alternative that has nothing to
            // fold. A tuple origin is the alternative this branch is for.
            //
            // Normalising the response side too would be the opposite error, and
            // a worse one: a canonical `Origin` answered by an
            // `Access-Control-Allow-Origin` that writes the default port out is a
            // check that fails in every user agent, because the serializer
            // produced no port and the field carries one. That finding is true
            // and stays.
            //
            // cite(Fetch § 4.10): "If the result of byte-serializing a request origin with request is not origin, then return failure."
            // cite(RFC 6454 § 6.2): "If the port part of the origin triple is different from the default port for the protocol given by the scheme part of the origin triple:"
            // The guard at the top of this body has already established that the
            // value is `null` or a `serialized-origin`, which is exactly what
            // the serializer accepts, so the fallback is unreachable from here
            // and is the value as written rather than a panic — the two readers
            // agreeing on what an origin is is the invariant, and an `expect`
            // would turn a future disagreement between them into a crash in a
            // linter.
            let serialized = crate::helpers::origin::ascii_serialized_origin(origin)
                .unwrap_or_else(|| origin.to_string());
            if acao_val != serialized {
                return Some(ctx.by_server().report_with(
                    &ACCESS_CONTROL_ALLOW_ORIGIN_CONFLICTING,
                    // The sentence names the serialization when it is not the
                    // text the client wrote, because that is the value the
                    // comparison was made against and an operator reading the
                    // request line would otherwise see two strings that look
                    // equal and a finding saying they are not.
                    if serialized == origin {
                        format!(
                            "Access-Control-Allow-Origin '{}' does not match request Origin '{}'",
                            crate::helpers::shown::shown_in_finding(&acao_val),
                            crate::helpers::shown::shown_in_finding(origin)
                        )
                    } else {
                        format!(
                            "Access-Control-Allow-Origin '{}' does not match request Origin '{}', \
                             whose origin serializes to '{}' — which is what the CORS check \
                             compares the field against",
                            crate::helpers::shown::shown_in_finding(&acao_val),
                            crate::helpers::shown::shown_in_finding(origin),
                            crate::helpers::shown::shown_in_finding(&serialized)
                        )
                    },
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &OriginMatchingForCors;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{
        make_headers_from_pairs, make_test_transaction, make_test_transaction_with_response,
    };

    #[rstest]
    fn no_origin_header_ignored() {
        let rule = OriginMatchingForCors;
        let tx = make_test_transaction_with_response(200, &[]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// An `Access-Control-Allow-Origin` written with no value is the field's
    /// own grammar rule's finding — `access_control_allow_origin_empty` — and
    /// not this rule's. `list_members` yields no members for it, so the
    /// `!= 1` test that separates one member from several used to answer the
    /// empty field with the entry written for the several: "must be a single
    /// value", said of a value that is not there and is therefore not
    /// multiple. Both directions are pinned, because renaming the finding here
    /// would be the same defect drawn twice.
    #[rstest]
    #[case("", None)]
    #[case("  ", None)]
    #[case(
        "https://a.example, https://b.example",
        Some("access_control_allow_origin_malformed")
    )]
    fn an_empty_allow_origin_is_not_a_value_that_is_multiple(
        #[case] acao: &str,
        #[case] expected: Option<&str>,
    ) {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", acao)]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://a.example")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.as_ref().map(|v| v.violation.as_str()),
            expected,
            "{acao:?}: {:?}",
            v.as_ref().map(|v| &v.message)
        );
    }

    /// The two productions the shared reader borrows report under their own
    /// ids, and the two verdicts about the field's own grammar under the
    /// field's — the mapping is total now, where it used to hand half the
    /// answers back for the caller to word.
    #[rstest]
    #[case("1http://example.com", Some("uri_scheme_leading_letter_missing"))]
    #[case("https://exa<mple.com", Some("uri_character_forbidden"))]
    #[case("https://example.com/p", Some("origin_path_forbidden"))]
    #[case("invalid-origin", Some("origin_malformed"))]
    fn an_origin_defect_reports_under_the_production_it_broke(
        #[case] origin: &str,
        #[case] expected: Option<&str>,
    ) {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://example.com")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", origin)]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, expected.unwrap_or_default(), "{}", v.message);
    }

    #[test]
    fn an_obs_text_octet_in_the_origin_is_a_syntax_finding() {
        use hyper::header::HeaderValue;

        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://example.com")],
        );
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            "origin",
            HeaderValue::from_bytes(b"https://exa\xffmple.com").expect("a field line"),
        );
        tx.request.headers = hdrs;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // The rule used to say nothing here: the value never reached the origin
        // syntax check, because the reader refused it first.
        let msg = v.expect("a finding").message;
        assert!(
            msg.starts_with("Invalid Origin header value 'https://exa\u{ff}mple.com'"),
            "{msg}"
        );
    }

    #[test]
    fn an_obs_text_octet_in_the_allowed_origin_does_not_match() {
        use hyper::header::HeaderValue;

        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(b"https://exa\xffmple.com").expect("a field line"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.expect("a finding").message,
            "Access-Control-Allow-Origin 'https://exa\u{ff}mple.com' does not match request Origin 'https://example.com'"
        );
    }

    #[rstest]
    fn no_acao_header_ignored() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        // response has no ACAO
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn valid_matching_origin_ok() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://example.com")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn wildcard_without_credentials_ok() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "*")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn wildcard_with_credentials_violation() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert_eq!(
            v.violation,
            "access_control_allow_origin_credentials_conflicting"
        );
        assert!(
            v.message.contains("answer with the requesting origin"),
            "the repair keeps the uncredentialed sharing `*` already gives: {}",
            v.message
        );
    }

    #[rstest]
    fn acao_mismatch_violation() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://other.com")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert!(v.message.contains("does not match request Origin"));
    }

    #[rstest]
    fn origin_null_matches_null() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "null")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "null")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The wildcard stands in front of credentialed sharing only when the
    /// credentials field turns it on, and the CORS check turns it on for the
    /// byte sequence `true` and nothing else. Every other value beside `*` is
    /// a response that shares with no credentialed request whatever the origin
    /// field says, so there is no pairing to report; the value is
    /// `access_control_allow_credentials_when_origin`'s `_invalid`, which the
    /// second half of this test asserts so the silence here is not the only
    /// word on it.
    #[rstest]
    #[case::the_literal(&["true"], true)]
    #[case::padded_with_ows(&["  true "], true)]
    #[case::upper_case(&["TRUE"], false)]
    #[case::title_case(&["True"], false)]
    #[case::a_digit(&["1"], false)]
    // The check gets the field, joining its lines: `true, true`.
    #[case::two_true_lines(&["true", "true"], false)]
    fn wildcard_pairs_only_with_the_byte_sequence_true(
        #[case] credentials: &[&str],
        #[case] pairs: bool,
    ) {
        let rule = OriginMatchingForCors;
        let mut headers = vec![("access-control-allow-origin", "*")];
        headers.extend(
            credentials
                .iter()
                .map(|c| ("access-control-allow-credentials", *c)),
        );
        let mut tx = make_test_transaction_with_response(200, &headers);
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.as_ref().map(|v| v.violation.as_str()),
            pairs.then_some("access_control_allow_origin_credentials_conflicting"),
            "{credentials:?}: {v:?}"
        );

        let owner = crate::rules::access_control_allow_credentials_when_origin::AccessControlAllowCredentialsWhenOrigin;
        let by_owner = crate::test_helpers::run_rule(
            &owner,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
        )
        .expect("the credentials rule reports every value beside `*`");
        assert_eq!(
            by_owner.violation,
            if pairs {
                "access_control_allow_credentials_conflicting"
            } else {
                "access_control_allow_credentials_invalid"
            },
            "{credentials:?}"
        );
    }

    #[rstest]
    fn acao_comma_list_violation() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://a, https://b")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://a")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert!(v.message.contains("single value"));
    }

    #[rstest]
    fn multiple_header_fields_violation() {
        let rule = OriginMatchingForCors;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://a")]);
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.append(
            "access-control-allow-origin",
            hyper::header::HeaderValue::from_static("https://b"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert!(v.message.contains("Multiple Access-Control-Allow-Origin"));
    }

    #[rstest]
    fn uppercase_null_origin_is_invalid() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "null")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "NULL")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }
    #[rstest]
    fn uppercase_null_acao_does_not_match_null_origin() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "NULL")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "null")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }
    #[rstest]
    fn lowercase_null_matches_null_origin() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "null")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "null")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }
    #[rstest]
    fn invalid_origin_header_violation() {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "*")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "bad://")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        // The helper now returns a generic message for missing authority,
        // so we simply check for the word "Origin" to avoid brittle tests.
        assert!(v.message.contains("Origin"));
    }

    /// The origin a value names, as the CORS check's left-hand side computes it.
    fn ids_and_messages(origin: &str, acao: &str) -> Vec<(String, String)> {
        let rule = OriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", acao)]);
        tx.request.headers = make_headers_from_pairs(&[("origin", origin)]);
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .iter()
        .map(|v| (v.violation.clone(), v.message.clone()))
        .collect()
    }

    /// **A value the grammar admits is not a value the serializer emits**, and
    /// the check compares against the serializer's output.
    ///
    /// `serialized-origin = scheme "://" host [ ":" port ]` derives
    /// `https://a.example:443` happily; RFC 6454 § 6.2 appends a port only where
    /// it differs from the scheme's default, and § 4 lower-cases the scheme and
    /// the host before the triple exists. So each request below asks from the
    /// same origin as the response answers, and the pair is correct.
    ///
    /// Every one of these was a `warn` attributed to the **server** — telling an
    /// origin its CORS configuration was broken because a client wrote a legal
    /// spelling of the same origin.
    #[rstest]
    #[case::https_default_port("https://a.example:443", "https://a.example")]
    #[case::http_default_port("http://a.example:80", "http://a.example")]
    #[case::upper_case_scheme_and_host("HTTPS://A.EXAMPLE", "https://a.example")]
    #[case::upper_case_host_only("https://A.Example", "https://a.example")]
    fn a_request_origin_is_compared_as_the_check_serializes_it(
        #[case] origin: &str,
        #[case] acao: &str,
    ) {
        assert!(
            ids_and_messages(origin, acao).is_empty(),
            "{origin:?} and {acao:?}: {:?}",
            ids_and_messages(origin, acao)
        );
    }

    /// **The other direction, and it is not the same question.** § 4.10 compares
    /// the serialization of the *request's* origin against the response field's
    /// value *as sent*, so nothing normalises the response side: a canonical
    /// `Origin` answered by a line that writes the default port out, or that
    /// upper-cases the host, is a check that fails in every user agent.
    ///
    /// This is what a repair normalising both sides would have silenced, and it
    /// is why the fold above is on one side only.
    #[rstest]
    #[case::response_writes_the_default_port("https://a.example", "https://a.example:443")]
    #[case::response_upper_cases_the_host("https://a.example", "https://A.EXAMPLE")]
    fn the_response_value_is_not_normalised(#[case] origin: &str, #[case] acao: &str) {
        let found = ids_and_messages(origin, acao);
        assert_eq!(
            found.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec!["access_control_allow_origin_conflicting"],
            "{origin:?} and {acao:?}"
        );
    }

    /// A port that is not a default is part of the origin, so a response that
    /// omits it answers a different origin. The serialization is the text here,
    /// and the sentence does not print the same string twice.
    #[test]
    fn a_port_that_is_not_a_default_stays_in_the_serialization() {
        let found = ids_and_messages("https://a.example:8443", "https://a.example");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "access_control_allow_origin_conflicting");
        assert!(found[0].1.contains("'https://a.example:8443'"), "{found:?}");
        assert!(!found[0].1.contains("serializes to"), "{found:?}");
    }

    /// Where the serialization is **not** the text the client wrote, the
    /// sentence names it: the comparison was made against that value, and an
    /// operator reading the request line would otherwise have to run § 6.2 by
    /// hand to see why the two strings printed are the ones that were compared.
    #[test]
    fn the_sentence_names_the_serialization_where_it_differs_from_the_line() {
        let found = ids_and_messages("HTTPS://A.EXAMPLE:8443", "https://b.example");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .1
                .contains("serializes to 'https://a.example:8443'"),
            "{found:?}"
        );
    }

    /// And where the serialization *is* the text the client wrote, the sentence
    /// does not print it twice.
    #[test]
    fn a_canonical_origin_needs_no_second_spelling_in_the_sentence() {
        let found = ids_and_messages("https://a.example", "https://b.example");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].1.contains("serializes to"), "{found:?}");
    }

    /// The fold belongs to the two schemes RFC 9110 gives a default port to.
    /// Under any other scheme there is nothing for a document here to elide the
    /// port against, so it stays part of the origin.
    #[test]
    fn a_scheme_with_no_default_port_here_keeps_its_port() {
        let found = ids_and_messages("ftp://a.example:443", "ftp://a.example");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "access_control_allow_origin_conflicting");
    }

    /// **The decline this body makes rests on three other declarations, and a
    /// decline resting on somebody else's declaration is only as good as an
    /// assertion about it.**
    ///
    /// A client's `Origin` defect ends the reading here, so the four
    /// response-side entries below it are not asked on that exchange — and they
    /// are the *server's*, so the peer that could act on them is told nothing.
    /// That is safe exactly while each is said somewhere else, which is a fact
    /// about two other rules' `violations()` and not about this file. Asserted
    /// by name, in the direction that fails: remove one of these from its own
    /// rule and this test goes red rather than the silence going unnoticed.
    ///
    /// The fourth, `access_control_allow_origin_conflicting`, is deliberately
    /// not in the list. It has no second declarer and needs none: the check
    /// compares against the serialization of the request's origin, and a value
    /// deriving from neither alternative of `origin-list-or-null` has none.
    #[test]
    fn the_response_side_findings_this_decline_rests_on_are_declared_elsewhere() {
        let by_the_field_rule: Vec<&str> =
            crate::rules::access_control_allow_origin_valid::AccessControlAllowOriginValid
                .violations()
                .iter()
                .map(|d| d.id)
                .collect();
        for id in [
            "field_line_duplicated",
            "access_control_allow_origin_malformed",
        ] {
            assert!(
                by_the_field_rule.contains(&id),
                "{id} is no longer declared by access_control_allow_origin_valid, so this rule's \
                 decline on a malformed Origin now loses it outright: {by_the_field_rule:?}"
            );
        }

        let by_the_credentials_rule: Vec<&str> =
            crate::rules::access_control_allow_credentials_when_origin::AccessControlAllowCredentialsWhenOrigin
                .violations()
                .iter()
                .map(|d| d.id)
                .collect();
        assert!(
            by_the_credentials_rule.contains(&"access_control_allow_credentials_conflicting"),
            "the wildcard-with-credentials fact is no longer stated by \
             access_control_allow_credentials_when_origin, so a malformed Origin now hides it \
             entirely: {by_the_credentials_rule:?}"
        );
    }

    #[test]
    fn needs_a_response() {
        let rule = OriginMatchingForCors;
        assert!(rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = OriginMatchingForCors;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("origin_matching_for_cors".into(), toml::Value::Table(table));
        rule.prepare(&cfg)?;
        Ok(())
    }
}
