// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Report the two things § 9.3.7 asks of an OPTIONS exchange that a captured
/// message can answer: a request carrying content with no `Content-Type`, and a
/// successful response that advertises none of the optional features this
/// specification gives a field name to.
///
/// **What this rule used to check.** It reported a successful OPTIONS response
/// with no `Allow` header field, under the message *"Successful OPTIONS response
/// SHOULD include an Allow header"*. No sentence says that. § 9.3.7's SHOULD is
/// about a *class* — *"any header that might indicate optional features
/// implemented by the server and applicable to the target resource"* — and
/// prints `Allow` as its example, while § 10.2.1 makes `Allow` itself a **MAY**
/// on every response other than a 405. So a server answering with
/// `Accept-Patch` and no `Allow` — RFC 5789 § 3.1's advice, in an OPTIONS
/// response, which is where that document asks for it — was reported for
/// obeying the sentence.
pub struct OptionsMethodCapabilities;

/// The response fields the specifications name as advertising an optional
/// feature implemented by the server and applicable to the target resource.
///
/// This is a *subset* of what § 9.3.7's SHOULD asks for, and the sentence says
/// so itself: the class it names ends *"including potential extensions not
/// defined by this specification"*, so no table can hold it. These are the ones
/// with a sentence behind them. `description()` states the boundary, because a
/// response advertising an extension field reads here exactly like a response
/// advertising nothing.
///
/// Presence is the whole test, for `Allow` by name: § 10.2.1 gives an empty
/// value a meaning — the resource allows no methods — so a server that sends
/// one has answered the question rather than declined it.
///
/// The third element is which field *sections* to look in, and it is per field
/// definition rather than per category: § 6.5.1 forbids a trailer field unless
/// the field's own definition permits it, and of these three only § 14.3 does.
// cite(RFC 9110 § 9.3.7): "A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow), including potential extensions not defined by this specification."
// cite(RFC 9110 § 10.2.1): "An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration."
// cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
const ADVERTISED_CAPABILITIES: [(&str, &str, bool); 3] = [
    // cite(RFC 9110 § 10.2.1): "The "Allow" header field lists the set of methods advertised as supported by the target resource."
    ("allow", "Allow", false),
    // cite(RFC 9110 § 14.3): "The "Accept-Ranges" field in a response indicates whether an upstream server supports range requests for the target resource."
    // cite(RFC 9110 § 14.3): "The Accept-Ranges field MAY be sent in a trailer section, but is preferred to be sent as a header field because the information is particularly useful for restarting large information transfers that have failed in mid-content (before the trailer section is received)."
    ("accept-ranges", "Accept-Ranges", true),
    // cite(RFC 5789 § 3.1): "Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method."
    ("accept-patch", "Accept-Patch", false),
];

impl Rule for OptionsMethodCapabilities {
    fn id(&self) -> &'static str {
        "options_method_capabilities"
    }

    /// § 9.3.7 addresses both ends: the content requirement is on the client and
    /// the advertisement is on the server. `Server` would mean "skip when there
    /// is no response", so the request-only lint — and every exchange whose
    /// upstream failed — would never measure the MUST the request had already
    /// broken when it was sent.
    // cite(RFC 9110 § 9.3.7): "A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Two sentences meet at this gate and both are load-bearing: the first
        // is why the rule looks at OPTIONS at all, the second is why the
        // comparison is exact. `options` is not the OPTIONS method, and a method
        // this specification does not define has no capability-advertising
        // semantics for a response to be measured against.
        // cite(RFC 9110 § 9.3.7): "The OPTIONS method requests information about the communication options available for the target resource, at either the origin server or an intervening intermediary."
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method != "OPTIONS" {
            return None;
        }

        // Content, not framing: the shared measurement reads § 6.4's octet
        // stream, so a chunked OPTIONS whose only chunk is the terminator
        // carries none, and an OPTIONS carrying an HTTP/2 DATA frame — which
        // declares no framing field at all — does.
        //
        // Absence is the finding here and nothing else is. The sentence asks for
        // a *valid* field, and a value that is empty or is not a media type is
        // `content_type_valid`'s — confirmed by running it, not by
        // reading it.
        // cite(RFC 9110 § 9.3.7): "A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type."
        if let Some(evidence) =
            crate::helpers::headers::content_evidence(&tx.request.headers, tx.request.body_length)
        {
            if !tx.request.headers.contains_key("content-type") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "OPTIONS request carries content ({evidence}) with no Content-Type header field; RFC 9110 § 9.3.7 says a client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type"
                    ),
                });
            }
        }

        let resp = tx.response.as_ref()?;

        // An asterisk target names no resource, and the SHOULD below asks for
        // headers "applicable to the target resource". There is nothing for such
        // a response to advertise: `Allow` lists the methods of a target
        // resource this request does not have.
        //
        // This reaches the asterisk over HTTP/1.1 only, and the limit is in the
        // capture rather than here: `proxy/http3.rs` records
        // `req.uri().to_string()` of a URI the h3 crate rebuilds from `:scheme`,
        // `:authority` and `:path`, so a `:path` of `*` is recorded as
        // `https://example.com*` — a string that does not even reparse to the
        // same target (the authority swallows the asterisk). Widening the
        // comparison would be guessing; recovering the form needs the capture to
        // keep it. Stated in `description()` because it costs an operator a
        // finding.
        // cite(RFC 9110 § 9.3.7): "An OPTIONS request with an asterisk ("*") as the request target (Section 7.1) applies to the server in general rather than to a specific resource."
        // cite(RFC 9110 § 9.3.7): "If the request target is not an asterisk, the OPTIONS request applies to the options that are available when communicating with the target resource."
        if tx.request.uri == "*" {
            return None;
        }

        // "Successful" is the name of the 2xx class, so that is the range.
        // cite(RFC 9110 § 15.3): "The 2xx (Successful) class of status code indicates that the client's request was successfully received, understood, and accepted."
        if !(200..300).contains(&resp.status) {
            return None;
        }

        // The SHOULD is about the class, not about `Allow`: asking for that
        // field by name would report a server exercising § 10.2.1's MAY, and the
        // one response where `Allow` is required is a 405, which is not 2xx and
        // is `status_405_allow_valid`'s.
        // cite(RFC 9110 § 10.2.1): "An origin server MUST generate an Allow header field in a 405 (Method Not Allowed) response and MAY do so in any other response."
        // cite(RFC 9110 § 9.3.7): "A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow), including potential extensions not defined by this specification."
        if !ADVERTISED_CAPABILITIES
            .iter()
            .any(|(lowercase, _, in_trailers)| {
                resp.headers.contains_key(*lowercase)
                    || (*in_trailers
                        && resp
                            .trailers
                            .as_ref()
                            .is_some_and(|t| t.contains_key(*lowercase)))
            })
        {
            let named: Vec<&str> = ADVERTISED_CAPABILITIES.iter().map(|(_, n, _)| *n).collect();
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Successful OPTIONS response ({}) carries none of {}; RFC 9110 § 9.3.7 says a server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource",
                    resp.status,
                    named.join(", ")
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Semantic OPTIONS Method Capabilities")
    }

    fn description(&self) -> &'static str {
        "Reports the two requirements RFC 9110 §9.3.7 places on an OPTIONS exchange that a captured message can answer. An OPTIONS request asks \"about the communication options available for the target resource\", so what the exchange is for is the advertisement in the response.\n\n**A request carrying content must say what it is.** §9.3.7: \"A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type.\" Content is §6.4's — the stream of octets after the header section, counted once framing has been taken off — so a `Transfer-Encoding: chunked` is not by itself content, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured its octet count decides; otherwise the request's own `Content-Length` does, which leaves a chunked request whose octets were not captured unmeasurable. Only the field's *absence* is reported here: a `Content-Type` that is empty or is not a media type is `content_type_valid`'s finding. The section adds that \"this specification does not define any use for such content\", so the requirement is about labelling what was sent, not about sending it.\n\n**A successful response should advertise something.** §9.3.7: \"A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow), including potential extensions not defined by this specification.\" That names a class, not a field, so this rule does not ask for `Allow` — §10.2.1 makes `Allow` a **MAY** on every response other than a 405, and the 405 that requires it is `status_405_allow_valid`'s. The finding is a successful response carrying none of the three fields a specification names as advertising an optional feature applicable to the target resource: `Allow` (§10.2.1), `Accept-Ranges` (§14.3), and `Accept-Patch` (RFC 5789 §3.1, which asks for it in an OPTIONS response by name). Presence is the whole test — §10.2.1 gives an empty `Allow` value the meaning \"the resource allows no methods\", which is an answer. `Accept-Ranges` also counts when it arrives in the trailer section, because §14.3 says it MAY be sent there; the other two are read from the header section only, since §6.5.1 forbids a trailer field unless the field's own definition permits it and neither definition does.\n\n**The limit of that finding.** The sentence ends by including \"potential extensions not defined by this specification\", so the class is open and no list can close it. A server advertising a capability under a field name this rule does not know reads here exactly like a server advertising nothing. Read the finding as \"nothing recognizable was advertised\", not as a violation of the SHOULD.\n\n**Not checked: an asterisk target.** §9.3.7 says an OPTIONS request with `*` as the request target \"applies to the server in general rather than to a specific resource\", and the SHOULD asks for headers applicable to the target resource. Such a response is not measured — **over HTTP/1.1**. Over HTTP/3 the capture does not keep the form: the request target is recorded as the string form of a URI rebuilt from `:scheme`, `:authority` and `:path`, so a `:path` of `*` arrives as `https://example.com*` and the asterisk is no longer distinguishable from part of the authority. An `OPTIONS *` over HTTP/3 is therefore measured, and may be reported for advertising nothing when there was nothing to advertise.\n\n**Not checked: where `Max-Forwards` came from.** §9.3.7's \"A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field\" is about who wrote a field, and no field of a message records its author. A capture cannot distinguish a client's `Max-Forwards` from one an intermediary invented."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7",
                note: "OPTIONS — the client `MUST` about `Content-Type`, the `SHOULD` to advertise, which names a class ending \"including potential extensions not defined by this specification\" rather than a field, the asterisk target that names no resource, and the `Max-Forwards` `MUST NOT` no capture can attribute",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "The method token is case-sensitive, which is why `OPTIONS` is matched exactly and a lowercase `options` is not an OPTIONS",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4",
                note: "Content — the octet stream left after framing is removed, which is what the `Content-Type` check measures instead of the presence of a framing field",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3",
                note: "2xx is the class named Successful, which is the range \"a successful response to OPTIONS\" means",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1",
                note: "`Allow` advertises the target resource's methods, is a `MAY` on any response other than a 405 — so it is not asked for by name — and an empty value of it means the resource allows no methods",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3",
                note: "`Accept-Ranges` advertises range-request support for the target resource — a second member of the class §9.3.7 asks for",
            },
            crate::rules::SpecRef {
                spec: "RFC 5789",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1",
                note: "`Accept-Patch` advertises the patch formats a resource accepts, and this section asks for it in an OPTIONS response by name",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The methods of the target resource"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A capability other than the method set — the class is what the SHOULD names"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nAccept-Patch: application/json-patch+json",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An asterisk target names no resource, so nothing is asked of the response"),
                snippet: "OPTIONS * HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Length: 0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Content in the request, labelled"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\nContent-Type: application/json\nContent-Length: 2\n\n{}\n\nHTTP/1.1 200 OK\nAllow: GET, OPTIONS",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A successful response that advertises nothing recognizable"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Content in the request with nothing saying what it is"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\nContent-Length: 2\n\n{}\n\nHTTP/1.1 200 OK\nAllow: GET, OPTIONS",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &OptionsMethodCapabilities;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, so `body_length` — the field the
    /// content finding rests on — and the request target are always stated
    /// rather than defaulted.
    fn make_tx(
        method: &str,
        target: &str,
        req_headers: &[(&str, &str)],
        body_length: Option<u64>,
        response: Option<(u16, &[(&str, &str)])>,
    ) -> crate::http_transaction::HttpTransaction {
        use crate::http_transaction::ResponseInfo;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.uri = target.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(req_headers);
        tx.request.body_length = body_length;
        tx.response = response.map(|(status, headers)| ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length: None,
            trailers: None,
        });
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = OptionsMethodCapabilities;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    /// The advertisement half. `Allow` is one member of the class, not the
    /// class: a response naming any of the three has answered.
    #[rstest]
    #[case(200, &[][..], true)]
    #[case(200, &[("allow", "GET, HEAD")][..], false)]
    #[case(200, &[("accept-ranges", "bytes")][..], false)]
    #[case(200, &[("accept-patch", "application/json-patch+json")][..], false)]
    #[case(204, &[][..], true)]
    #[case(201, &[("allow", "POST")][..], false)]
    #[case(404, &[][..], false)]
    #[case(405, &[][..], false)]
    #[case(300, &[][..], false)]
    fn advertisement_cases(
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &[("host", "example.com")],
            None,
            Some((status, headers)),
        );
        let v = run(&tx);
        assert_eq!(
            v.is_some(),
            expect_violation,
            "status {status} with {headers:?}: {v:?}"
        );
    }

    /// § 10.2.1 gives an empty value a meaning, so sending one is an answer.
    #[test]
    fn empty_allow_value_is_an_advertisement() {
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &[("host", "example.com")],
            None,
            Some((200, &[("allow", "")])),
        );
        assert!(run(&tx).is_none());
    }

    /// § 14.3's `Accept-Ranges` MAY arrive in the trailer section, and what the
    /// response advertised is one question asked across both sections. The other
    /// two field definitions permit no such thing, so § 6.5.1 keeps them out.
    #[rstest]
    #[case("accept-ranges", false)]
    #[case("allow", true)]
    #[case("accept-patch", true)]
    fn a_trailer_advertises_only_where_the_field_definition_permits_it(
        #[case] field: &str,
        #[case] expect_violation: bool,
    ) {
        let mut tx = make_tx(
            "OPTIONS",
            "/r",
            &[("host", "example.com")],
            None,
            Some((200, &[])),
        );
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[(field, "bytes")]),
        );
        let v = run(&tx);
        assert_eq!(v.is_some(), expect_violation, "{field} in a trailer: {v:?}");
    }

    /// The defect this rule was written with: a server taking RFC 5789 § 3.1's
    /// advice, in the response that document names, was reported for it.
    #[test]
    fn accept_patch_alone_is_not_a_finding() {
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &[("host", "example.com")],
            None,
            Some((200, &[("accept-patch", "text/example")])),
        );
        assert!(run(&tx).is_none());
    }

    /// An asterisk target names no resource for a capability to apply to.
    #[test]
    fn asterisk_target_is_not_measured() {
        let tx = make_tx(
            "OPTIONS",
            "*",
            &[("host", "example.com")],
            None,
            Some((200, &[])),
        );
        assert!(run(&tx).is_none());
    }

    /// § 9.1: the method token is case-sensitive, so `options` is another method.
    #[test]
    fn lowercase_method_is_not_options() {
        let tx = make_tx(
            "options",
            "/r",
            &[("host", "example.com")],
            None,
            Some((200, &[])),
        );
        assert!(run(&tx).is_none());
    }

    /// The content half, against § 6.4's octets rather than a framing field.
    #[rstest]
    // Captured octets with no label.
    #[case(&[("content-length", "5")][..], Some(5), true)]
    // Captured octets, labelled.
    #[case(&[("content-length", "5"), ("content-type", "application/json")][..], Some(5), false)]
    // Nothing captured, and the sender's own declaration is what is left.
    #[case(&[("content-length", "5")][..], None, true)]
    // A framing field is not content: the only chunk is the terminator.
    #[case(&[("transfer-encoding", "chunked")][..], Some(0), false)]
    // Content over a version that declares no framing field at all.
    #[case(&[][..], Some(9), true)]
    // No content, so the sentence does not apply.
    #[case(&[("content-length", "0")][..], Some(0), false)]
    fn content_type_cases(
        #[case] headers: &[(&str, &str)],
        #[case] body_length: Option<u64>,
        #[case] expect_violation: bool,
    ) {
        let mut req: Vec<(&str, &str)> = vec![("host", "example.com")];
        req.extend_from_slice(headers);
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &req,
            body_length,
            Some((200, &[("allow", "GET, OPTIONS")])),
        );
        let v = run(&tx);
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{headers:?} body_length={body_length:?}: {v:?}"
        );
    }

    /// The content requirement is the client's, so it is measured on a capture
    /// that never drew a response — which `RuleScope::Server` used to skip.
    #[test]
    fn content_finding_survives_a_missing_response() {
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &[("host", "example.com"), ("content-length", "5")],
            Some(5),
            None,
        );
        let v = run(&tx).expect("a request-only capture still broke the MUST");
        assert!(v.message.contains("Content-Type"));
    }

    /// An empty or malformed value belongs to the rule that owns the field's
    /// syntax; this one reports absence only.
    #[test]
    fn a_present_content_type_is_not_judged_here() {
        let tx = make_tx(
            "OPTIONS",
            "/r",
            &[
                ("host", "example.com"),
                ("content-length", "5"),
                ("content-type", ""),
            ],
            Some(5),
            Some((200, &[("allow", "GET")])),
        );
        assert!(run(&tx).is_none());
    }

    #[test]
    fn non_options_request_is_ignored() {
        let tx = make_tx(
            "GET",
            "/r",
            &[("host", "example.com")],
            None,
            Some((200, &[])),
        );
        assert!(run(&tx).is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = OptionsMethodCapabilities;
        assert_eq!(rule.id(), "options_method_capabilities");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// Nothing else runs a rule's published examples through it. Each snippet
    /// here is a request, optionally the octets it carries, then the response —
    /// and the body block is what makes `body_length` real rather than assumed.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        fn fields<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(&'a str, &'a str)> {
            lines
                .map(|line| {
                    line.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"))
                })
                .collect()
        }

        let mut saw_a_finding = false;
        for ex in OptionsMethodCapabilities.examples() {
            let blocks: Vec<&str> = ex.snippet.split("\n\n").collect();
            let (request, body, response) = match blocks.as_slice() {
                [request, response] => (*request, None, *response),
                [request, body, response] => (*request, Some(*body), *response),
                _ => panic!("not a request and a response: {:?}", ex.snippet),
            };

            let mut request = request.lines();
            let request_line = request.next().expect("a request has a request line");
            let parts: Vec<&str> = request_line.split(' ').collect();
            let [method, target, "HTTP/1.1"] = parts.as_slice() else {
                panic!("not a request line: {request_line:?}");
            };

            let mut response = response.lines();
            let status_line = response.next().expect("a response has a status line");
            let status: u16 = status_line
                .strip_prefix("HTTP/1.1 ")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|code| code.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {status_line:?}"));

            let response_fields = fields(response);
            let tx = make_tx(
                method,
                target,
                &fields(request),
                body.map(|b| b.len() as u64),
                Some((status, &response_fields)),
            );

            let found = run(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "options_method_capabilities");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
