// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Reports a redirect whose `Location` names the resource the request already
/// addressed — a redirection to where the client already is.
///
/// The comparison is between two absolute forms, not two strings: the target
/// URI is reconstructed from the request-target and `Host`, and the `Location`
/// value is resolved against it. Everything else about the field — its grammar,
/// an empty value, more than one field line, and which statuses may carry it at
/// all — belongs to other rules and is declined here.
pub struct RedirectChainValid;

/// What the response's own status definition says the `Location` value names,
/// or `None` for a status whose definition gives the field no *elsewhere* to
/// point at.
///
/// The set is not the 3xx class. `redirect_status_and_location_valid`
/// exempts the whole class because its licensing sentence — §10.2.2's *"For 3xx
/// (Redirection) responses"* — names the class; the sentences licensing *this*
/// finding are the individual status definitions, and they are what a status is
/// in or out of the set for. Five of them say the URI is a **different** or a
/// **new** one, and a 300's `Location` is one of the alternatives it offers.
///
/// cite(RFC 9110 § 10.2.2): "For 3xx (Redirection) responses, the Location value refers to the preferred target resource for automatically redirecting the request."
fn location_names_another_resource(status: u16) -> Option<&'static str> {
    match status {
        // cite(RFC 9110 § 15.4.1): "the target resource has more than one representation, each with its own more specific identifier"
        // cite(RFC 9110 § 15.4.1): "If the server has a preferred choice, the server SHOULD generate a Location header field containing a preferred choice's URI reference."
        300 => Some(
            "a 300 (Multiple Choices) offers representations \"each with its own more specific identifier\", and the field carries \"a preferred choice's URI reference\" (RFC 9110 §15.4.1)",
        ),
        // cite(RFC 9110 § 15.4.2): "The 301 (Moved Permanently) status code indicates that the target resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs."
        301 => Some(
            "a 301 (Moved Permanently) states that the target resource \"has been assigned a new permanent URI\" (RFC 9110 §15.4.2)",
        ),
        // cite(RFC 9110 § 15.4.3): "The 302 (Found) status code indicates that the target resource resides temporarily under a different URI."
        302 => Some(
            "a 302 (Found) states that the target resource \"resides temporarily under a different URI\" (RFC 9110 §15.4.3)",
        ),
        // The one status that says it outright rather than by implication.
        // cite(RFC 9110 § 15.4.4): "The 303 (See Other) status code indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, which is intended to provide an indirect response to the original request."
        // cite(RFC 9110 § 15.4.4): "Note that the new URI in the Location header field is not considered equivalent to the target URI."
        303 => Some(
            "a 303 (See Other) redirects to \"a different resource\", and §15.4.4 adds that the URI in the field \"is not considered equivalent to the target URI\" (RFC 9110 §15.4.4)",
        ),
        // cite(RFC 9110 § 15.4.8): "The 307 (Temporary Redirect) status code indicates that the target resource resides temporarily under a different URI and the user agent MUST NOT change the request method if it performs an automatic redirection to that URI."
        307 => Some(
            "a 307 (Temporary Redirect) states that the target resource \"resides temporarily under a different URI\" (RFC 9110 §15.4.8)",
        ),
        // cite(RFC 9110 § 15.4.9): "The 308 (Permanent Redirect) status code indicates that the target resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs."
        308 => Some(
            "a 308 (Permanent Redirect) states that the target resource \"has been assigned a new permanent URI\" (RFC 9110 §15.4.9)",
        ),
        // The three 3xx codes whose own definitions name no other resource, one
        // arm each because each is exempt for its own reason, and all three
        // ahead of the class arm below so that arm cannot swallow them.
        //
        // A 304 redirects the client to something it already holds rather than
        // to another URI, so a `Location` equal to the target starts no
        // redirection and closes no cycle.
        // cite(RFC 9110 § 15.4.5): "the server is therefore redirecting the client to make use of that stored representation as if it were the content of a 200 (OK) response"
        304 => None,
        // cite(RFC 9110 § 15.4.6): "The 305 (Use Proxy) status code was defined in a previous version of this specification and is now deprecated (Appendix B of [RFC7231])."
        305 => None,
        // cite(RFC 9110 § 15.4.7): "The 306 status code was defined in a previous version of this specification, is no longer used, and the code is reserved."
        306 => None,
        // A 3xx nobody registered is a 300 to every conforming recipient, so it
        // inherits §15.4.1's sentence — and §15.4 says the field may be followed
        // precisely where the code is not understood, which is this arm.
        //
        // cite(RFC 9110 § 15): "However, a client MUST understand the class of any status code, as indicated by the first digit, and treat an unrecognized status code as being equivalent to the x00 status code of that class."
        // cite(RFC 9110 § 15.4): "If a Location header field (Section 10.2.2) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood."
        // cite(RFC 9110 § 15.4): "The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request."
        s if (300..400).contains(&s) => Some(
            "an unregistered 3xx is equivalent to a 300 (Multiple Choices) for every recipient (RFC 9110 §15), whose Location carries \"a preferred choice's URI reference\" (§15.4.1)",
        ),
        // A `201 Created` is the status this rule used to report most often, and
        // the case it reported is the one §15.3.2 *defines*: a `PUT` that creates
        // the resource at the request's own target names that target, and the
        // response would mean the same thing carrying no field at all.
        //
        // cite(RFC 9110 § 10.2.2): "For 201 (Created) responses, the Location value refers to the primary resource created by the request."
        // cite(RFC 9110 § 15.3.2): "The primary resource created by the request is identified by either a Location header field in the response or, if no Location header field is received, by the target URI."
        _ => None,
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_15_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
    note: "Redirection 3xx: a client SHOULD detect and intervene in cyclical redirections, and MAY follow a Location even where the specific status code is not understood",
};
const RFC_9110_10_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
    note: "Location: a relative reference is resolved against the target URI, and a fragmentless value inherits the target's fragment",
};
const RFC_9110_15_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2",
    note: "201 Created: with no Location field the resource created is the target URI, which is why a 201 naming its own target is not reported",
};
const RFC_9112_3_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.3",
    note: "Reconstructing the target URI: the authority comes from Host when the request-target has none, and the scheme from the connection — which the capture does not record",
};
const RFC_3986_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("5"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-5",
    note: "Reference resolution: the transform that makes a Location value and a request-target comparable",
};
const RFC_3986_6_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("6.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2",
    note: "Syntax-Based Normalization: all three of its normalizations are applied to both sides after resolution — the percent-encoding decoded where the octet is unreserved, the dot segments removed, and the case of the path and query left alone. §6.2.3's scheme-based normalization is not applied",
};

impl RuleMeta for RedirectChainValid {
    fn id(&self) -> &'static str {
        "redirect_chain_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Redirect To The Request's Own Target")
    }

    fn description(&self) -> &'static str {
        "Reports a redirect whose `Location` resolves to the target URI of the request it answers — a redirection to where the client already is. Following it produces the same request, and following that produces the same response.\n\n**The status set is the statuses whose own definition says the field names another resource.** Five say it in as many words — `301` and `308` a *new permanent* URI (RFC 9110 §15.4.2, §15.4.9), `302` and `307` a *different* URI (§15.4.3, §15.4.8), and `303` adds that the URI in the field *\"is not considered equivalent to the target URI\"* (§15.4.4) — and a `300`'s `Location` is *\"a preferred choice's URI reference\"* among representations *\"each with its own more specific identifier\"* (§15.4.1). An unregistered 3xx is a `300` to every conforming recipient (§15) and is reported the same way.\n\n**`304`, `305`, `306` and `201` are not reported.** A `304` redirects the client to a representation it already holds rather than to another URI; `305` is deprecated and `306` reserved, so neither defines anything to follow. A `201 Created` naming the request's own target is the case §15.3.2 *defines* — a `PUT` that creates the resource where it was addressed — and that response would mean the same thing carrying no field at all.\n\n**The comparison is between absolute forms, not between strings.** The target URI is reconstructed from the request-target and the `Host` field (RFC 9112 §3.3), and the `Location` is resolved against it (§10.2.2, RFC 3986 §5), so `page`, `/dir/page` and `https://host/dir/page` are recognised as one resource, and a value naming a different host is not reported however its path reads. Both sides then get RFC 3986 §6.2.2's syntax-based normalization, so a dot segment and a needlessly percent-encoded `unreserved` character are spellings rather than resources: `/a%2Db` and `/a-b` are one path, and — since §2.3 names the period among the octets a normalizer decodes — so are `/dir/%2E%2E/dir/page` and `/dir/page`. `%2F` is not decoded, because that would move a segment boundary the sender never wrote (§2.4). §6.2.3's scheme-based normalization is **not** applied, so a `Location` writing out the scheme's default port does not compare equal to a target that left it off.\n\n**Two things the capture cannot decide, and the rule declines both.** A request-target in origin-form carries no scheme — RFC 9112 §3.3 takes it from whether the connection was secured, which is not in the message — so a `Location` naming a scheme is not compared; the case that would otherwise be reported is the ordinary HTTP-to-HTTPS redirect. Likewise a reference naming a host is not compared when no `Host` field says which host was addressed.\n\n**This is advice.** No sentence forbids a server from sending it. The status definitions above *declare* what the field names rather than requiring anything of it, and the one requirement in the area — §15.4's *\"A client SHOULD detect and intervene in cyclical redirections\"* — is addressed to the client, which is the role this rule is performing. What the finding buys is that a redirect no client can resolve becomes visible.\n\n**Longer cycles are not detected, and the rule reads no history.** A cycle spanning two or more resources needs a history that spans resources; the state layer's origin-scoped query derives that origin from the request-target alone, so it is empty for the origin-form target an HTTP/1.1 request carries. Only the one-step cycle is reported.\n\nThe field's grammar, an empty value, and a response carrying more than one `Location` field line are `location_header_uri_valid`'s findings; a `Location` on a status with no use for one is `redirect_status_and_location_valid`'s; a redirect status carrying *no* `Location` is `location_on_redirect_present`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_15_4,
            RFC_9110_10_2_2,
            RFC_9110_15_3_2,
            RFC_9112_3_3,
            RFC_3986_5,
            RFC_3986_6_2_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the field names somewhere else)"),
                snippet: "GET /old HTTP/1.1\nHost: example.com\n\nHTTP/1.1 301 Moved Permanently\nLocation: /new",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(canonicalizing to another host: same path, different authority)"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 301 Moved Permanently\nLocation: https://www.example.com/a",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the created resource is the target — RFC 9110 §15.3.2)"),
                snippet: "PUT /widgets/123 HTTP/1.1\nHost: example.com\n\nHTTP/1.1 201 Created\nLocation: /widgets/123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the field names the request's own target)"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 301 Moved Permanently\nLocation: /a",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a relative-path reference resolving to the same resource)"),
                snippet: "GET /dir/page HTTP/1.1\nHost: example.com\n\nHTTP/1.1 302 Found\nLocation: page",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(same authority, same path, written out in full)"),
                snippet: "GET http://example.com/a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 303 See Other\nLocation: http://example.com/a",
            },
        ]
    }
}

impl Rule for RedirectChainValid {
    /// `Location` is defined in §10.2, *Response Context Fields*, and every
    /// sentence this rule enforces is a status-code definition. There is no
    /// request half to read.
    ///
    /// cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            let resp = tx.response.as_ref()?;

            let referent = location_names_another_resource(resp.status)?;

            // Everything about the field's own shape is `location_header_uri_valid`'s.
            // Each decline below is a case that rule already reports, and reporting
            // it a second time here would say the same thing with less of the reason.
            let lines = resp.headers.get_all("location").iter().count();
            if lines != 1 {
                // No field: nothing to compare. Several field lines: the value in
                // force is a `URI-reference` naming neither of the resources the
                // sender wrote, so resolving it would compare against a URI nobody
                // meant.
                return None;
            }

            // Read as the sender wrote it. `to_str` admits only visible US-ASCII, so
            // a `Location` carrying %xFF read through it becomes "this response has
            // no Location field" — and the previous version of this rule instead
            // announced it as "not valid UTF-8", a claim about the value that is
            // wrong twice over: every octet `to_str` refuses is outside the URI
            // alphabet, and most of them are perfectly good UTF-8.
            //
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
            let raw = combined_field_value_as_written(&resp.headers, "location")?;
            let value = trim_ows(&raw);

            // An empty value *is* the self-referential case — a same-document
            // reference resolving to the target URI — and the owning rule says so in
            // those words. Nothing is gained by saying it twice.
            if value.is_empty() {
                return None;
            }

            // A value carrying an octet no `URI-reference` admits identifies no
            // resource at all, so there is nothing to resolve. The octet is named by
            // the rule that owns the grammar.
            if crate::helpers::uri::find_non_uri_char(value).is_some() {
                return None;
            }

            // The comparison is between absolute forms. A `Location` is a
            // `URI-reference`, which means nothing on its own: `page`, `/dir/page`
            // and `https://host/dir/page` can all name the resource just requested,
            // and only resolution against the target URI decides which.
            //
            // cite(RFC 9110 § 7.1): "A URI reference is resolved to its absolute form in order to obtain the "target URI"."
            // cite(RFC 9110 § 10.2.2): "When it has the form of a relative reference ([URI], Section 4.2), the final value is computed by resolving it against the target URI ([URI], Section 5)."
            let target_path_and_query =
                crate::helpers::uri::extract_path_and_query_from_request_target(&tx.request.uri)
                    .map(|p| crate::helpers::uri::normalize_path_and_query(&p))?;

            // Neither side's fragment takes part: §10.2.2 hands a fragmentless
            // `Location` the target's own fragment, so two references differing only
            // there redirect to the same place. Both helpers drop it.
            //
            // cite(RFC 9110 § 10.2.2): "If the Location value provided in a 3xx (Redirection) response does not have a fragment component, a user agent MUST process the redirection as if the value inherits the fragment component of the URI reference used to generate the target URI (i.e., the redirection inherits the original reference's fragment, if any)."
            let location_path_and_query = crate::helpers::uri::resolve_reference_path_and_query(
                &target_path_and_query,
                value,
            )?;

            // All of §6.2.2 is applied to both sides, by the helper above: two
            // references differing in the percent-encoding of an `unreserved`
            // character are equivalent under §6.2.2.2, and `Location: /a%2Db`
            // answering a request for `/a-b` is a redirect to the resource just
            // requested however it is spelled. §6.2.3's scheme-based normalization
            // is not applied — see the default-port note below — so the two sides
            // still have to agree about anything only the `http` scheme's own
            // definition makes equivalent.
            if location_path_and_query != target_path_and_query {
                return None;
            }

            // An equal path decides nothing on its own: a `Location` naming another
            // host with the same path is where the web keeps its canonicalizing
            // redirects, and this rule used to report every one of them, because an
            // origin-form request-target carries no authority to disagree with. The
            // target URI's authority is in `Host` for exactly that reason.
            let target_authority =
                crate::helpers::uri::target_uri_authority(&tx.request.uri, &tx.request.headers);
            let location_authority = crate::helpers::uri::reference_authority(value);
            match (target_authority.as_deref(), location_authority.as_deref()) {
                // cite(RFC 3986 § 6.2.2.1): "the scheme and host are case-insensitive and therefore should be normalized to lowercase"
                (Some(target), Some(location)) if !target.eq_ignore_ascii_case(location) => {
                    return None
                }
                // The reference names a host and nothing in the message says which
                // host was addressed, so the two cannot be compared.
                (None, Some(_)) => return None,
                // The reference defines no authority of its own and inherits the
                // target's, whatever that is.
                _ => {}
            }

            // Two authorities differing only in a default port are equivalent under
            // §6.2.3, and are not recognised here. That is a *scheme-based*
            // normalization — the rung above the one the paths get — and it needs
            // the scheme, which an origin-form request-target does not carry. An
            // under-report, and the safe direction for a finding this rule offers as
            // advice.

            // The last component, and the one the capture does not record. A
            // request-target in origin-form carries no scheme: RFC 9112 §3.3 takes it
            // from whether the connection was secured, which is connection context
            // and not part of the message. So a scheme-bearing `Location` under an
            // origin-form request cannot be compared — and the case hiding there is
            // the plain HTTP-to-HTTPS redirect, which names this same authority and
            // this same path and is not a redirect to the same resource at all.
            //
            // cite(RFC 9112 § 3.3): "The target URI is the request-target when the request-target is in absolute-form."
            // cite(RFC 9112 § 3.3): "Otherwise, if the request is received over a secured connection, the target URI's scheme is "https"; if not, the scheme is "http"."
            let target_origin = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);
            let location_origin = crate::helpers::uri::extract_origin_if_absolute(value);
            match (target_origin.as_deref(), location_origin.as_deref()) {
                (Some(target), Some(location)) if !target.eq_ignore_ascii_case(location) => {
                    return None
                }
                (None, Some(_)) => return None,
                _ => {}
            }

            // cite(RFC 9110 § 15.4): "A client SHOULD detect and intervene in cyclical redirections (i.e., "infinite" redirection loops)."
            Some(self.cited(&RFC_9110_15_4, ctx.severity, format!(
                    "Location '{}' resolves to '{}', the target URI of the request it answers, so the response redirects the client to where it already was: {}. A client that follows it issues the same request again — RFC 9110 §15.4 asks one to detect and intervene in cyclical redirections, and this is the shortest one there is",
                    value.escape_debug(),
                    location_path_and_query.escape_debug(),
                    referent
                )))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RedirectChainValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, so no test can be silent about the
    /// three inputs the comparison reads: the request-target, the `Host` field
    /// that completes it, and the `Location` field lines.
    fn exchange(
        target: &str,
        host: Option<&str>,
        status: u16,
        locations: &[&str],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = target.to_string();
        let mut req_headers = hyper::HeaderMap::new();
        if let Some(h) = host {
            req_headers.insert(
                hyper::header::HeaderName::from_static("host"),
                hyper::header::HeaderValue::from_str(h).expect("a test Host value"),
            );
        }
        tx.request.headers = req_headers;

        let mut headers = hyper::HeaderMap::new();
        for l in locations {
            headers.append(
                hyper::header::HeaderName::from_static("location"),
                hyper::header::HeaderValue::from_bytes(l.as_bytes())
                    .expect("a test Location value"),
            );
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers,
            body_length: Some(0),
            trailers: None,
        });
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RedirectChainValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(
            crate::rules::Rule::scope(&RedirectChainValid),
            crate::rules::RuleScope::Server
        );
    }

    /// Each of the six statuses whose definition names another resource, with
    /// the sentence it is reported against named in the message.
    #[rstest]
    #[case(300, "more specific identifier")]
    #[case(301, "new permanent URI")]
    #[case(302, "resides temporarily under a different URI")]
    #[case(303, "not considered equivalent to the target URI")]
    #[case(307, "resides temporarily under a different URI")]
    #[case(308, "new permanent URI")]
    fn each_status_is_reported_against_its_own_sentence(
        #[case] status: u16,
        #[case] expected: &str,
    ) {
        let v = judge(&exchange("/a", Some("example.com"), status, &["/a"]))
            .unwrap_or_else(|| panic!("{status} naming its own target is not reported"));
        assert!(
            v.message.contains(expected),
            "{status}: {expected:?} missing from {:?}",
            v.message
        );
    }

    /// The 3xx codes with no *elsewhere* in their definition, and the 201 whose
    /// definition makes naming the target the ordinary case. The 201 and the 304
    /// were both reported before this rule was audited.
    #[rstest]
    #[case(201)]
    #[case(304)]
    #[case(305)]
    #[case(306)]
    #[case(200)]
    #[case(404)]
    fn a_status_whose_definition_names_no_other_resource_is_not_reported(#[case] status: u16) {
        assert!(judge(&exchange("/a", Some("example.com"), status, &["/a"])).is_none());
    }

    /// §15 makes an unregistered 3xx a 300, so it carries §15.4.1's sentence.
    #[rstest]
    #[case(309)]
    #[case(310)]
    #[case(350)]
    #[case(399)]
    fn an_unregistered_3xx_is_reported_as_the_300_it_is_equivalent_to(#[case] status: u16) {
        let v = judge(&exchange("/a", Some("example.com"), status, &["/a"]))
            .unwrap_or_else(|| panic!("{status} naming its own target is not reported"));
        assert!(v.message.contains("unregistered 3xx"), "{:?}", v.message);
    }

    /// Resolution, not string comparison: every one of these `Location` values
    /// names the resource the request already addressed.
    #[rstest]
    #[case("/dir/page", "page")]
    #[case("/dir/page", "/dir/page")]
    #[case("/dir/page", "./page")]
    #[case("/dir/page", "../dir/page")]
    #[case("/dir/page", "/dir/./page")]
    #[case("/a?x=1", "/a?x=1")]
    #[case("/a", "/a#section")]
    #[case("/a", "//example.com/a")]
    // §6.2.2.2: a triplet standing for an `unreserved` character names the same
    // resource as the character, in either direction and in the query too.
    #[case("/a-b", "/a%2Db")]
    #[case("/a%2Db", "/a-b")]
    #[case("/a?x=~1", "/a?x=%7E1")]
    // …and §2.3 names the period among those octets, so this is a dot segment.
    #[case("/dir/page", "/dir/%2E%2E/dir/page")]
    fn a_reference_resolving_to_the_target_is_reported(#[case] target: &str, #[case] loc: &str) {
        assert!(
            judge(&exchange(target, Some("example.com"), 301, &[loc])).is_some(),
            "{loc:?} against {target:?}"
        );
    }

    /// The canonicalizing redirect, which this rule reported for every
    /// origin-form request because the request-target has no authority to
    /// disagree with. The authority is in `Host`, which is what that field is for.
    #[rstest]
    #[case("https://www.example.com/a")]
    #[case("//www.example.com/a")]
    fn a_reference_naming_another_host_is_not_reported(#[case] loc: &str) {
        assert!(judge(&exchange("/a", Some("example.com"), 301, &[loc])).is_none());
    }

    /// The scheme is connection context, not message content. The plain
    /// HTTP-to-HTTPS redirect names this authority and this path, and is not a
    /// redirect to the same resource.
    #[test]
    fn a_scheme_bearing_reference_over_an_origin_form_target_is_not_compared() {
        assert!(judge(&exchange(
            "/a",
            Some("example.com"),
            301,
            &["https://example.com/a"]
        ))
        .is_none());
    }

    /// With an absolute-form request-target the scheme *is* on the wire, and
    /// both directions become decidable.
    #[test]
    fn an_absolute_form_target_supplies_the_scheme() {
        assert!(judge(&exchange(
            "http://example.com/a",
            Some("example.com"),
            301,
            &["http://example.com/a"]
        ))
        .is_some());
        assert!(judge(&exchange(
            "http://example.com/a",
            Some("example.com"),
            301,
            &["https://example.com/a"]
        ))
        .is_none());
    }

    /// A reference naming a host when nothing says which host was addressed.
    #[test]
    fn a_host_naming_reference_with_no_host_field_is_not_compared() {
        assert!(judge(&exchange("/a", None, 301, &["//example.com/a"])).is_none());
    }

    /// `Host` is a singleton, and a message carrying two of them is one a server
    /// must answer with a 400 (RFC 9112 §3.2). Reading the first would pick an
    /// authority by position; the target's is unknown, so the comparison stops.
    /// A reference that names *no* authority is unaffected — it inherits the
    /// target's whatever that turns out to be.
    #[test]
    fn two_host_field_lines_leave_the_target_authority_unknown() {
        let mut tx = exchange("/a", Some("a.example"), 301, &["//a.example/a"]);
        tx.request.headers.append(
            hyper::header::HeaderName::from_static("host"),
            hyper::header::HeaderValue::from_static("b.example"),
        );
        assert!(judge(&tx).is_none());

        let mut tx = exchange("/a", Some("a.example"), 301, &["/a"]);
        tx.request.headers.append(
            hyper::header::HeaderName::from_static("host"),
            hyper::header::HeaderValue::from_static("b.example"),
        );
        assert!(judge(&tx).is_some());
    }

    /// Different resources — the ordinary case, which the rule must stay quiet
    /// about.
    #[rstest]
    #[case("/a", "/b")]
    #[case("/dir/page", "other")]
    #[case("/a?x=1", "/a?x=2")]
    #[case("/a", "/a/")]
    // The other side of §6.2.2.2: `%2F` is not an `unreserved` character, so
    // decoding it would move a segment boundary the sender never wrote. `/a%2Fb`
    // is one segment and `/a/b` is two.
    #[case("/a/b", "/a%2Fb")]
    fn a_reference_naming_another_resource_is_not_reported(
        #[case] target: &str,
        #[case] loc: &str,
    ) {
        assert!(
            judge(&exchange(target, Some("example.com"), 301, &[loc])).is_none(),
            "{loc:?} against {target:?}"
        );
    }

    /// Shapes `location_header_uri_valid` owns and reports, each declined
    /// here rather than reported twice with less of the reason. The value
    /// carrying %xFF is where this rule used to claim "not valid UTF-8".
    #[rstest]
    #[case::no_field(&[])]
    #[case::two_field_lines(&["/a", "/a"])]
    #[case::empty_value(&[""])]
    #[case::an_octet_no_uri_admits(&["/\u{ff}"])]
    #[case::a_space(&["/a b"])]
    fn a_finding_the_grammar_rule_owns_is_declined(#[case] locations: &[&str]) {
        assert!(judge(&exchange("/a", Some("example.com"), 301, locations)).is_none());
    }

    /// …and the decline costs no coverage: the owner reports each of them. Run,
    /// not read — the claim "another rule reports this" is a claim about code
    /// that can just be called.
    #[rstest]
    #[case(&["/a", "/a"])]
    #[case(&[""])]
    #[case::an_octet_no_uri_admits(&["/\u{ff}"])]
    #[case::a_space(&["/a b"])]
    fn the_owning_rule_reports_what_this_one_declines(#[case] locations: &[&str]) {
        let tx = exchange("/a", Some("example.com"), 301, locations);
        let owner = crate::rules::location_header_uri_valid::LocationHeaderUriValid;
        assert!(
            crate::test_helpers::run_rule(
                &owner,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "location_header_uri_valid",
                ]),
            )
            .is_some(),
            "{locations:?}"
        );
    }

    /// Request-target forms carrying no path, so there is no target URI to
    /// resolve against.
    #[rstest]
    #[case("*")]
    #[case("example.com:443")]
    fn a_request_target_with_no_path_is_not_compared(#[case] target: &str) {
        assert!(judge(&exchange(target, Some("example.com"), 301, &["/a"])).is_none());
    }

    /// An exchange-shaped example: request line and fields, a blank line, then
    /// the status line and its fields. Parsed rather than assumed, so an example
    /// written in the wrong shape fails here instead of being judged as
    /// something it is not.
    fn published_exchange(snippet: &str) -> crate::http_transaction::HttpTransaction {
        fn field(l: &str) -> (&str, &str) {
            l.split_once(": ")
                .unwrap_or_else(|| panic!("not a header line: {l:?}"))
        }

        let (req, resp) = snippet
            .split_once("\n\n")
            .expect("an example is a request, a blank line, then a response");

        let mut req_lines = req.lines();
        let request_line = req_lines.next().expect("a request line");
        let mut parts = request_line.split(' ');
        let method = parts.next().expect("a method");
        let target = parts.next().expect("a request-target");
        assert_eq!(parts.next(), Some("HTTP/1.1"), "in {request_line:?}");

        let mut resp_lines = resp.lines();
        let status_line = resp_lines.next().expect("a status line");
        assert!(
            status_line.starts_with("HTTP/1.1 "),
            "not a status line: {status_line:?}"
        );
        let status: u16 = status_line
            .split(' ')
            .nth(1)
            .expect("a status code")
            .parse()
            .expect("a numeric status code");

        let host = req_lines
            .map(field)
            .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.to_string());
        let locations: Vec<&str> = resp_lines
            .map(field)
            .filter(|(n, _)| n.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v)
            .collect();

        let mut tx = exchange(target, host.as_deref(), status, &locations);
        tx.request.method = method.to_string();
        tx
    }

    /// Nothing runs a rule's own `examples()` through the rule, so a Compliant
    /// example it reports ships as guidance. The previous set published a third
    /// snippet describing a check that rested on no sentence, in a shape no
    /// guard could have parsed.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in RedirectChainValid.examples() {
            let found = judge(&published_exchange(ex.snippet));
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "redirect_chain_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
