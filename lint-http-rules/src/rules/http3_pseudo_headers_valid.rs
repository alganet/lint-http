// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::authority::{
    AUTHORITY_TUNNEL_MISSING, AUTHORITY_TUNNEL_USERINFO_FORBIDDEN, AUTHORITY_USERINFO_FORBIDDEN,
    RFC_9110_9_3_6, RFC_9113_8_3_1, RFC_9113_8_5, RFC_9114_4_3_1, RFC_9114_4_4,
};
use crate::violations::request_target::{
    REQUEST_TARGET_ASTERISK_FORBIDDEN, REQUEST_TARGET_PATH_MISSING, RFC_9110_7_1,
};
use crate::violations::uri::{
    host_and_port, scheme_name, RFC_3986_3_1, RFC_3986_3_2_2, RFC_3986_3_2_3,
    URI_HOST_BRACKET_FORBIDDEN, URI_HOST_CHARACTER_FORBIDDEN, URI_HOST_CLOSING_BRACKET_MISSING,
    URI_HOST_IP_LITERAL_MALFORMED, URI_PORT_CHARACTER_FORBIDDEN, URI_SCHEME_CHARACTER_FORBIDDEN,
    URI_SCHEME_EMPTY, URI_SCHEME_LEADING_LETTER_MISSING,
};
use crate::violations::ViolationDef;

pub struct Http3PseudoHeadersValid;

/// The authority's and the scheme's defects, which is all this rule borrows —
/// the same eight the HTTP/2 twin declares, for the same values.
///
/// § 4.3.1 conveys the authority portion of the target URI and the scheme
/// portion of the request target; neither is a production this document writes,
/// so a bracket, a host character, a port digit or a scheme's first letter is
/// the same defect here, in a `Host` field and in an HTTP/2 request. **The two
/// version rules had read the same value to different depths**: the twin has
/// measured this authority against `uri-host [ ":" port ]` since it was
/// converted, and this one only ever looked for an `@`.
///
/// **The asterisk is the ninth, and it is not the authority's.** A `:path` of
/// `*` on a method other than `OPTIONS` is the request *target* being in a form
/// that method may not use, which RFC 9110 § 7.1 states once for every version —
/// so the entry lives in
/// [`request_target`](crate::violations::request_target) and is declared here,
/// by the HTTP/2 twin, and by the rule that reads an HTTP/1.x request-line.
///
/// **A CONNECT that names no destination is borrowed too**, and it is the
/// field's rather than the target's:
/// RFC 9114 § 4.4 says the host and port ride in `:authority` over this version
/// and RFC 9113 § 8.5 says it over the other, so the entry names both and this
/// rule reports it wherever the target carried no authority and no `Host` field
/// carried one either. **The three sites this rule had for that message are now
/// one** — an empty target, an origin-form target with no `Host`, and a target of
/// any other form with neither — because the shape a target arrived in says what
/// the sender attempted and not what a recipient is missing.
///
/// Everything else here is about *which* pseudo-header a message carries and
/// where — a non-CONNECT request with no authority and no `Host`. None of that
/// is a defect of a production, and the documents that require it write no
/// grammar to name it after.
static DECLARED: &[&ViolationDef] = &[
    &URI_HOST_CLOSING_BRACKET_MISSING,
    &URI_HOST_IP_LITERAL_MALFORMED,
    &URI_HOST_BRACKET_FORBIDDEN,
    &URI_HOST_CHARACTER_FORBIDDEN,
    &URI_PORT_CHARACTER_FORBIDDEN,
    &URI_SCHEME_EMPTY,
    &URI_SCHEME_LEADING_LETTER_MISSING,
    &URI_SCHEME_CHARACTER_FORBIDDEN,
    &REQUEST_TARGET_ASTERISK_FORBIDDEN,
    &AUTHORITY_USERINFO_FORBIDDEN,
    &AUTHORITY_TUNNEL_USERINFO_FORBIDDEN,
    &REQUEST_TARGET_PATH_MISSING,
    &AUTHORITY_TUNNEL_MISSING,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9114_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3",
    note: "HTTP Control Data",
};
const RFC_3986_3_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("3.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1",
    note: "User Information — the sentence asking an application not to render what \
           follows the first colon of a userinfo, which is why both findings here \
           withhold the password half",
};
const RFC_9110_9_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
    note: "Overview of methods — `method = token`, and the token is case-sensitive, which is why CONNECT and OPTIONS are matched exactly here as they are over HTTP/2",
};
const RFC_9114_4_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("4.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2",
    note: "Response Pseudo-Header Fields",
};
impl RuleMeta for Http3PseudoHeadersValid {
    fn id(&self) -> &'static str {
        "http3_pseudo_headers_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "error"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 Pseudo-Headers Validity")
    }

    fn description(&self) -> &'static str {
        "HTTP/3 requests encode control data as pseudo-header fields. This rule reads what each of them conveyed, and the first thing it checks is that every non-CONNECT request includes a non-empty `:path` pseudo-header field.\n\n**A request naming no method at all is not reported here.** §4.3.1 requires exactly one `:method`, and over this version an absent one and an empty one reassemble into the same capture: a method of no characters, which is `method = token`'s one-character floor. `request_method_token_valid` reports that on every version, so the finding is left there rather than given a second name; what a value naming no method does here is stop the rule, since neither the CONNECT restrictions nor the asterisk's one method have anything to turn on. The same goes for a method carrying an octet outside `tchar`, and for one written with whitespace around it: the value is read as written, because trimming it would hide the space from this rule and from nowhere else. `http2_pseudo_headers_valid` surrendered the same question earlier and for the same reason.\n\n**The method is compared as written.** It is case-sensitive (RFC 9110 §9.1: \"The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names\"), so `connect` is a method these documents do not define and owns none of CONNECT's restrictions, and `options` is not the method the asterisk-form is left to. The fold this replaced *suppressed* findings: a lowercase `connect` took the tunnel branch and skipped the `:path` requirement, and a lowercase `options` was handed the asterisk.\n\nFor schemes with a mandatory authority component (including `http` and `https`), the HTTP/3 specification requires that the request contain either an `:authority` pseudo-header field or a `Host` header field. This rule enforces that requirement by checking that at least one of `:authority` or `Host` is present. **A CONNECT is asked the same question once**: §4.4 puts the host and port of the tunnel destination in `:authority`, a capture shows that field reassembled into the target — or, where a library moved it, as a `Host` field — and a request carrying neither names nothing to open a tunnel to. That is one finding whether the target arrived empty, as a path or as an asterisk, since the shape says what the sender attempted rather than what a recipient is missing; it used to be three, answered differently from how the HTTP/2 twin answered them. It does not validate the `:scheme` pseudo-header, because the canonical transaction model used by lint-http does not retain scheme information for origin-form requests.\n\n**The deprecated userinfo subcomponent is reported where it can be seen.** RFC 9114 §4.3.1 forbids `:authority` from including it for URIs of scheme `http` or `https`, and the capture shows `:authority` only where the transport reassembled it into an absolute-form target — which is also the one place the scheme the sentence gates on is on the wire, so the gate and the evidence arrive together or not at all. A CONNECT's `:authority` is §4.4's host-and-port tunnel destination, with no scheme to gate on and no third component, so a userinfo in an authority-form target is reported outright — while an absolute-form CONNECT target is a conforming extended CONNECT and a malformed basic one with nothing in a capture to choose between them, and is declined here as the HTTP/2 twin declines it. Both findings withhold the password half (RFC 3986 §3.2.1). The twin sentence for HTTP/2 (RFC 9113 §8.3.1) is `http2_pseudo_headers_valid`'s.\n\n**This rule reads requests only.** RFC 9114 §4.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation here. The range that value must fall in is RFC 9110 §15's and is the same for every HTTP version — §4.3.2 states none of its own — so an out-of-range status is reported by `status_code_valid_range`, whatever version carried it. This rule used to report it too, but only when both ends spoke HTTP/3."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9114_4_3,
            RFC_9114_4_3_1,
            // The other version's copy of the userinfo MUST NOT, declared for
            // the reason the twin declares this one's: the entry both rules
            // report names both sections, because neither document governs the
            // other's version.
            RFC_9113_8_3_1,
            // Where a CONNECT's target is defined for every version, which is
            // what both version documents describe `:authority` by pointing at.
            // The tunnel entry names it and its findings carry it.
            RFC_9110_9_3_6,
            RFC_3986_3_2_1,
            RFC_9110_9_1,
            RFC_9114_4_3_2,
            RFC_9114_4_4,
            // The other version's account of a CONNECT's construction, declared
            // for the reason RFC 9113 § 8.3.1 above is: the entry for a request
            // that names no destination names both documents, and this rule
            // never reads a message either of them alone governs.
            RFC_9113_8_5,
            RFC_9110_7_1,
            RFC_3986_3_1,
            RFC_3986_3_2_2,
            RFC_3986_3_2_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/3\nHost: example.com\nAccept: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "OPTIONS * HTTP/3\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "CONNECT example.com:443 HTTP/3",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 200 OK\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/3\nAccept: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET * HTTP/3\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the deprecated userinfo subcomponent in :authority)"),
                snippet: "GET https://user@example.com/resource HTTP/3",
            },
        ]
    }
}

impl Rule for Http3PseudoHeadersValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // Only applies to HTTP/3 transactions. The version gate is scoping, not a
            // normative check, so it carries no cite; each requirement below cites the
            // sentence it enforces. What it reads is the major digit and not a string:
            // this version has no version field on the wire, so the value is one a
            // writer chose, and `http_version` is where the production lives.
            if !crate::http_version::is_major(&tx.request.version, 3) {
                return None;
            }

            // A request naming no method at all stops this rule rather than
            // being reported by it. § 4.3.1 does require exactly one `:method`,
            // and over this version an absent one and an empty one reassemble
            // into the same capture — but that capture is a method of no
            // characters, which is `method = token`'s one-character floor and is
            // reported by `request_method_token_valid` on every version. Two ids
            // for one absence is what this catalogue exists to remove, and the
            // HTTP/2 twin had already surrendered the same question for the same
            // reason. What is left here is that a value naming no method names
            // nothing for the branches below to turn on: neither the CONNECT
            // restrictions nor the asterisk's one method.
            //
            // (The `:scheme` half of the same sentence is not checked either —
            // the canonical model does not retain a scheme for origin-form
            // requests, as the description says.)
            // cite(RFC 9114 § 4.3.1): "All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4."
            //
            // Read as written. `method = token` is `1*tchar`, which admits no
            // whitespace for a trim to find and no empty string, so a value
            // failing it derives from no `method` — and trimming it here hid a
            // leading space from *this* rule without hiding it from the rule
            // that reports it, which is what the twin found when it stopped
            // trimming.
            // cite(RFC 9110 § A): "method = token minute = 2DIGIT"
            let method = tx.request.method.as_str();
            if method.is_empty() || crate::helpers::token::find_invalid_token_char(method).is_some()
            {
                return None;
            }

            // Compared as written, because the method token is case-sensitive:
            // `connect` is a method these documents do not define and owns none
            // of CONNECT's restrictions. The fold this replaces *suppressed*
            // findings — a lowercase `connect` took the tunnel branch and
            // skipped the `:path` requirement, a lowercase `options` was handed
            // the asterisk — and the twin had already settled the same question
            // the same way.
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
            // cite(RFC 9114 § 4.4): "The :method pseudo-header field is set to "CONNECT""
            let is_connect = method == "CONNECT";

            if is_connect {
                // Whether this request names a tunnel destination at all. It had
                // been three questions here — an empty target, an origin-form
                // target with no `Host`, a target of any other form with neither
                // — which answered differently for the same message and left the
                // HTTP/2 twin disagreeing with two of the three. The shape a
                // target arrived in says what the sender was attempting; what a
                // recipient is missing is the same thing in all of them, so it
                // is one finding.
                //
                // A `Host` field answers it, because a capture cannot separate
                // an authority a sender wrote there from one a library moved
                // there out of `:authority` — the reading the origin-form site
                // already made, now made for every form. The entry carries it,
                // names § 4.4 and RFC 9113 § 8.5, and leaves the message to name
                // the section governing the version this rule reads.
                // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to"
                let uri_trimmed = tx.request.uri.trim();
                let authority =
                    crate::helpers::uri::extract_authority_from_request_target(uri_trimmed);
                if authority.is_none() && !tx.request.headers.contains_key("host") {
                    return Some(ctx.report_with(
                        &AUTHORITY_TUNNEL_MISSING,
                        format!(
                            "HTTP/3 CONNECT request target '{}' names no host and port, and no \
                             'Host' field names one either: a CONNECT's ':authority' is the host \
                             and port to connect to (RFC 9114 §4.4)",
                            crate::helpers::shown::shown_in_finding(uri_trimmed)
                        ),
                    ));
                }

                // A CONNECT's `:authority` has two components and no third: the
                // host and port to connect to. This is not the scheme question
                // the non-CONNECT branch asks — the field here is a tunnel
                // destination, not an http(s) URI's authority — so the '@' is
                // reported whatever came before it, under its own entry rather
                // than the sibling one written for `http` and `https`. The
                // sentence that entry carries is RFC 9110 § 9.3.6's, which
                // states the two-component form once for every version and is
                // what § 4.4 describes this field by. The password half is
                // withheld from the finding (RFC 3986 § 3.2.1, at the shared
                // helper).
                //
                // Only an authority-form target is judged. An absolute-form
                // CONNECT target is a conforming extended CONNECT and a malformed
                // basic one with nothing in a capture to choose between them —
                // the same decline the HTTP/2 twin publishes — and § 4.4's
                // sentence describes the basic form only.
                // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to"
                if let Some(authority) = authority
                    .filter(|a| a.contains('@'))
                    .filter(|_| crate::helpers::uri::scheme_authority_marker(uri_trimmed).is_none())
                {
                    let shown = crate::helpers::uri::userinfo_password_withheld(&authority)
                        .unwrap_or(authority);
                    return Some(ctx.report_with(
                        &AUTHORITY_TUNNEL_USERINFO_FORBIDDEN,
                        format!(
                            "HTTP/3 CONNECT ':authority' '{}' carries a userinfo subcomponent and its '@' delimiter: the field is only the host and port to connect to",
                            crate::helpers::shown::shown_in_finding(&shown)
                        ),
                    ));
                }

                // `uri-host [ ":" port ]` is one question with one answer, and
                // the shared reader is where it lives — the same call the HTTP/2
                // twin makes on the same value. § 4.4 names the two components
                // and writes neither, so the bracket, the address inside it and
                // the port's digits answer to RFC 3986.
                // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to"
                if let Some(authority) = crate::helpers::uri::extract_authority_from_request_target(
                    uri_trimmed,
                )
                .filter(|_| crate::helpers::uri::scheme_authority_marker(uri_trimmed).is_none())
                {
                    if let Err(defect) =
                        crate::helpers::uri::validate_host_and_optional_port(&authority)
                    {
                        return Some(ctx.report_with(
                            host_and_port(defect),
                            format!(
                                "HTTP/3 CONNECT ':authority' '{}' is not a host and port: {}",
                                crate::helpers::shown::shown_in_finding(&authority),
                                defect.message()
                            ),
                        ));
                    }
                }
            } else {
                // Non-CONNECT: the request-target is either the asterisk-form (OPTIONS
                // only) or a path. RFC 9110 § 7.1 permits "*" for OPTIONS and forbids it
                // for every other method.
                //
                // Both sentences are quoted on the entry, which the HTTP/2 twin
                // and the HTTP/1.x rule declare too: the asterisk is one defect
                // over three spellings of one element, and § 7.1 is written in
                // the version-independent document for that reason.
                let uri_trimmed = tx.request.uri.trim();
                if uri_trimmed == "*" {
                    // Read as written for the reason above: `options` is not the
                    // method § 7.1 leaves the asterisk to, and folding here
                    // handed it the form.
                    // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
                    if method != "OPTIONS" {
                        return Some(ctx.report_with(
                            &REQUEST_TARGET_ASTERISK_FORBIDDEN,
                            format!(
                                "Asterisk ('*') is the ':path' value of a server-wide OPTIONS \
                                 request and of nothing else, and this request's ':method' is \
                                 '{method}'"
                            ),
                        ));
                    }
                } else {
                    // The entry names this section and RFC 9113 § 8.3.1 for the
                    // other version, so the message names the one governing
                    // here. An absent `:path` and a blank one reassemble into the
                    // same target, which is the reading the entry carries.
                    let has_path =
                        crate::helpers::uri::extract_path_from_request_target(uri_trimmed)
                            .is_some();
                    if !has_path {
                        return Some(
                            ctx.report_with(
                                &REQUEST_TARGET_PATH_MISSING,
                                "HTTP/3 request names no ':path': every non-CONNECT request sends \
                             exactly one, and an 'http' or 'https' URI with no path component \
                             sends '/' (RFC 9114 §4.3.1)"
                                    .into(),
                            ),
                        );
                    }
                }

                // HTTP/3 always runs over QUIC/TLS, so the scheme is always http or
                // https, both of which have a mandatory authority component — the
                // requirement applies to every non-CONNECT request.
                // cite(RFC 9114 § 4.3.1): "If the :scheme pseudo-header field identifies a scheme that has a mandatory authority component (including "http" and "https"), the request MUST contain either an :authority pseudo-header field or a Host header field."
                let authority =
                    crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri);
                let has_host = tx.request.headers.contains_key("host");
                if authority.is_none() && !has_host {
                    return Some(
                        self.cited(
                            &RFC_9114_4_3_1,
                            ctx.severity,
                            "HTTP/3 request must include ':authority' pseudo-header or Host header"
                                .into(),
                        ),
                    );
                }

                // § 4.3.1's userinfo MUST NOT, readable exactly where the
                // userinfo is. The deprecated subcomponent travels in
                // `:authority`, the capture shows that field only where the
                // transport reassembled it into an absolute-form target — and an
                // absolute-form target is also the one place the scheme the
                // sentence gates on is on the wire, so the gate and the evidence
                // arrive together or not at all. **The twin sentence for HTTP/2
                // is on the same entry**, which names both documents because
                // neither governs the other's version, so the message names the
                // section that governs this one. The password half is withheld
                // from the finding (RFC 3986 § 3.2.1, at the shared helper).
                if let Some(marker) = crate::helpers::uri::scheme_authority_marker(uri_trimmed) {
                    // The scheme is the characters before the marker, and the
                    // helper carries the production. Nothing here asks whether it
                    // is one anybody serves — this pseudo-header is not
                    // restricted to http and https — only whether it is a scheme
                    // name at all, which is the reading the twin already makes.
                    // cite(RFC 9114 § 4.3.1): "Contains the scheme portion of the target URI (Section 3.1 of [URI])."
                    if let Some(defect) = crate::helpers::uri::scheme_if_present(uri_trimmed) {
                        return Some(ctx.report_with(
                            scheme_name(defect),
                            format!(
                                "Request target's scheme is not a scheme name: {}",
                                defect.message()
                            ),
                        ));
                    }

                    let scheme = &uri_trimmed[..marker];

                    if let Some(authority) = authority.as_ref().filter(|a| a.contains('@')) {
                        if scheme.eq_ignore_ascii_case("http")
                            || scheme.eq_ignore_ascii_case("https")
                        {
                            let shown = crate::helpers::uri::userinfo_password_withheld(authority)
                                .unwrap_or_else(|| authority.clone());
                            return Some(ctx.report_with(
                                &AUTHORITY_USERINFO_FORBIDDEN,
                                format!(
                                    "HTTP/3 ':authority' '{}' of an '{scheme}' target includes the deprecated userinfo subcomponent and its '@' delimiter (RFC 9114 §4.3.1)",
                                    crate::helpers::shown::shown_in_finding(&shown)
                                ),
                            ));
                        }
                    }

                    // The same `uri-host [ ":" port ]` reading the CONNECT branch
                    // makes, on the authority this target reassembled.
                    // cite(RFC 9114 § 4.3.1): "Contains the authority portion of the target URI (Section 3.2 of [URI])."
                    if let Some(ref authority) = authority {
                        if let Err(defect) =
                            crate::helpers::uri::validate_host_and_optional_port(authority)
                        {
                            return Some(ctx.report_with(
                                host_and_port(defect),
                                format!(
                                    "HTTP/3 ':authority' '{}' is not a host and port: {}",
                                    crate::helpers::shown::shown_in_finding(authority),
                                    defect.message()
                                ),
                            ));
                        }
                    }
                }
            }

            // **The response half is not this rule's.** This branch used to report a
            // `:status` outside 100–599, and the constraint it enforced was RFC 9110
            // § 15's, not HTTP/3's: RFC 9114 § 4.3.2 defines the field as carrying "the
            // HTTP status code; see Section 15 of [HTTP]" and states no range of its
            // own. Behind the major-version gate above, the same out-of-range
            // status over HTTP/1.1 or HTTP/2 went unreported here and the HTTP/3 one was
            // reported twice — `status_code_valid_range` asks it of every
            // version. Same shape as the three checks `http3_status_code_valid`
            // surrendered for RFC 9110 § 15.2.
            //
            // What RFC 9114 § 4.3.2 does require of a response — that the field be
            // present at all — cannot fail in this model: `ResponseInfo.status` is a
            // `u16` that always holds a value, so a response with no `:status` has no
            // representation to check.
            //
            // cite(RFC 9114 § 4.3.2): "For responses, a single ":status" pseudo-header field is defined that carries the HTTP status code; see Section 15 of [HTTP]."
            // cite(RFC 9114 § 4.3.2): "This pseudo-header field MUST be included in all responses; otherwise, the response is malformed (see Section 4.1.2)."

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Http3PseudoHeadersValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3.0".into();
        tx
    }

    fn make_h3_transaction_with_response(
        status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp_headers);
        tx.request.version = "HTTP/3.0".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/3.0".into();
        }
        tx
    }

    /// The authority and the scheme answer to the same ids the HTTP/2 twin
    /// reports, on the same values — the reading this rule was missing.
    #[rstest]
    #[case("https://exa mple.com/p", "uri_host_character_forbidden")]
    #[case("https://[::1/p", "uri_host_closing_bracket_missing")]
    #[case("https://example.com:80a/p", "uri_port_character_forbidden")]
    #[case("1https://example.com/p", "uri_scheme_leading_letter_missing")]
    fn an_authority_or_scheme_defect_answers_to_its_production(
        #[case] target: &str,
        #[case] expected: &str,
    ) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = target.into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, expected, "{}", v.message);
    }

    /// A CONNECT's authority is measured too, and its port is where the twin
    /// looks first.
    #[rstest]
    fn a_connect_authority_is_measured_against_the_production() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:80a".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "uri_port_character_forbidden", "{}", v.message);
    }

    // --- A method that names nothing ---

    /// § 4.3.1 asks for exactly one `:method`, and over this version a request
    /// that sent none and one that sent an empty value arrive as the same
    /// capture: a method of no characters, which is `method = token`'s
    /// one-character floor. The rule that owns the production reports it on
    /// every version, so this one stops rather than giving the absence a second
    /// name — the handover the HTTP/2 twin made first. The whitespace cases are
    /// the same handover from the other side: `1*tchar` admits none of it, and
    /// the trim that used to run here hid a leading space from this rule and
    /// from nobody else.
    #[rstest]
    #[case("")]
    #[case("   ")]
    #[case(" GET")]
    #[case("GET ")]
    #[case("GE T")]
    #[case("GE\u{20AC}T")]
    fn a_value_that_is_no_method_stops_the_rule(#[case] method: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = method.into();
        tx.request.uri = "/resource".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none(),
            "{method:?}"
        );

        // That rule reads a required `registered_methods` array, and an absent
        // one stops the whole rule rather than only its case finding — so the
        // handover has to be exercised with a configuration a deployment would
        // actually have.
        let owner = crate::rules::request_method_token_valid::RequestMethodTokenValid;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]);
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        table.insert(
            "registered_methods".to_string(),
            toml::Value::Array(vec![toml::Value::String("GET".into())]),
        );
        cfg.rules
            .insert(owner.id().to_string(), toml::Value::Table(table));
        assert!(
            crate::test_helpers::run_rule(
                &owner,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .is_some(),
            "{method:?}"
        );
    }

    // --- the deprecated userinfo subcomponent ---

    fn judge(method: &str, uri: &str) -> Option<String> {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = method.into();
        tx.request.uri = uri.into();
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    /// § 4.3.1's MUST NOT names the two schemes it is about, and the capture
    /// shows `:authority` where the transport reassembled it into an
    /// absolute-form target — the one place the scheme is on the wire too.
    #[rstest]
    #[case("https://user@example.com/p", true)]
    #[case("http://user:pass@example.com/p", true)]
    #[case("HTTPS://user@example.com/p", true)]
    // Another scheme is outside the sentence.
    #[case("ftp://user@example.com/p", false)]
    // No userinfo, nothing to report.
    #[case("https://example.com/p", false)]
    fn userinfo_is_reported_for_http_and_https_targets(#[case] uri: &str, #[case] reported: bool) {
        let message = judge("GET", uri);
        assert_eq!(
            message.as_deref().is_some_and(|m| m.contains("userinfo")),
            reported,
            "{uri}: {message:?}"
        );
    }

    /// A CONNECT's `:authority` is § 4.4's host and port, with no scheme to
    /// gate on: the '@' is reported whatever came before it.
    #[test]
    fn connect_authority_with_userinfo_is_reported() {
        let msg = judge("CONNECT", "user@example.com:443").expect("reported");
        assert_eq!(
            msg,
            "HTTP/3 CONNECT ':authority' 'user@example.com:443' carries a userinfo subcomponent \
             and its '@' delimiter: the field is only the host and port to connect to"
        );
        assert_eq!(judge("CONNECT", "example.com:443"), None);

        // An absolute-form CONNECT target is a conforming extended CONNECT
        // and a malformed basic one, with nothing in a capture to choose
        // between them — the HTTP/2 twin's decline, mirrored here, so the
        // § 4.4 wording is never pinned on a target § 4.4 may not describe.
        assert_eq!(judge("CONNECT", "https://user@example.com/ws"), None);
    }

    /// Both findings withhold the password half (RFC 3986 § 3.2.1): the
    /// finding is about credentials arriving where a server logs, and a lint
    /// report must not be one more place they are written in clear.
    #[test]
    fn userinfo_findings_withhold_the_password() {
        let msg = judge("GET", "https://user:s3cret@example.com/p").expect("reported");
        assert_eq!(
            msg,
            "HTTP/3 ':authority' 'user:...@example.com' of an 'https' target includes the \
             deprecated userinfo subcomponent and its '@' delimiter (RFC 9114 §4.3.1)"
        );
        assert!(!msg.contains("s3cret"), "{msg}");

        let msg = judge("CONNECT", "user:s3cret@example.com:443").expect("reported");
        assert!(msg.contains("'user:...@example.com:443'"), "{msg}");
        assert!(!msg.contains("s3cret"), "{msg}");
    }

    // --- :path pseudo-header required for non-CONNECT ---

    #[test]
    fn get_with_path_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_without_path_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "example.com:443".into(); // authority-form, no path
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn options_asterisk_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_non_options_is_violation() {
        // Asterisk-form is only permitted with OPTIONS (RFC 9110 §7.1).
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    #[rstest]
    #[case("POST")]
    #[case("PUT")]
    #[case("DELETE")]
    #[case("PATCH")]
    #[case("HEAD")]
    fn asterisk_non_options_methods_are_violation(#[case] bad_method: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = bad_method.into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    // --- :authority or Host required ---

    #[test]
    fn origin_form_without_host_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn absolute_form_has_authority_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers = hyper::HeaderMap::new(); // no Host needed

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_without_host_or_authority_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    // --- CONNECT ---

    #[test]
    fn connect_with_authority_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// A CONNECT that names no destination is one finding whatever shape its
    /// target took. These four were three separate answers here — and the HTTP/2
    /// twin agreed with only some of them — until the question became one: does
    /// anything in this request name a host and port?
    #[rstest]
    #[case("")]
    #[case("   ")]
    #[case("/ws")]
    #[case("*")]
    fn a_connect_naming_no_destination_anywhere_is_one_finding(#[case] target: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = target.into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("reported");
        assert_eq!(v.violation, "authority_tunnel_missing", "{target}");
        assert!(v.message.contains("names no host and port"), "{target}");
    }

    /// A `Host` field is the other place the destination arrives, and a capture
    /// cannot tell one a sender wrote there from one a library moved there out
    /// of `:authority`. The origin-form site read it that way already; every
    /// shape does now, and the HTTP/2 twin answers these the same.
    #[rstest]
    #[case("")]
    #[case("/ws")]
    #[case("*")]
    fn a_host_field_names_the_destination_the_target_did_not(#[case] target: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = target.into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{target}: {:?}", v.map(|v| v.message));
    }

    #[test]
    fn connect_asterisk_without_host_is_violation() {
        // CONNECT with "*" URI: extract_authority returns None, no Host → violation.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_asterisk_with_host_is_ok() {
        // CONNECT with "*" URI but Host header present → ok.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com:443")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_authority_form_without_host_is_ok() {
        // Authority-form (host:port) is valid for CONNECT even without Host header.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Response :status ---

    #[test]
    fn response_valid_status_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(200, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The status range is RFC 9110 § 15's and holds for every version, so it is
    /// `status_code_valid_range`'s finding and not this rule's. These cases
    /// pin the decline: each was asserted as a violation here until the branch was
    /// removed, and each is still reported — over HTTP/3 as over every other
    /// version — by the rule that owns the question.
    #[rstest]
    #[case(0)]
    #[case(99)]
    #[case(600)]
    #[case(1000)]
    fn out_of_range_status_is_not_this_rules_finding(#[case] status: u16) {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(status, &[]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");

        let owner = crate::rules::status_code_valid_range::StatusCodeValidRange;
        assert!(
            crate::test_helpers::run_rule(
                &owner,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
            )
            .is_some(),
            "status {status} over HTTP/3 is reported by nobody"
        );
    }

    #[rstest]
    #[case(100)]
    #[case(200)]
    #[case(301)]
    #[case(404)]
    #[case(500)]
    #[case(599)]
    fn response_valid_status_range_is_ok(#[case] status: u16) {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/2.0")]
    #[case("HTTP/2.0")]
    fn non_h3_version_is_skipped(#[case] version: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.into();
        tx.request.method = "".into(); // would be a violation for HTTP/3

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Response version gating ---

    #[test]
    fn response_non_h3_version_not_checked() {
        // HTTP/3 request but HTTP/1.1 upstream response (reverse-proxy).
        let rule = Http3PseudoHeadersValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(0, &[]);
        tx.request.version = "HTTP/3.0".into();
        // Response version stays HTTP/1.1 — status 0 should not be flagged.

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn request_only_no_response_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/".into();
        tx.response = None;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_both() {
        let rule = Http3PseudoHeadersValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "http3_pseudo_headers_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    // --- RFC edge cases ---

    #[test]
    fn connect_ipv6_authority_is_ok() {
        // CONNECT with bracketed IPv6 authority (RFC 9114 §4.4).
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1]:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn extended_connect_with_scheme_and_path_is_ok() {
        // Extended CONNECT (RFC 9220) includes :scheme, :path, :authority.
        // We do not flag this because we cannot distinguish basic from extended
        // CONNECT in the canonical data model.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "https://example.com/ws".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn post_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "POST".into();
        tx.request.uri = "/submit".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn head_absolute_uri_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "HEAD".into();
        tx.request.uri = "https://example.com/resource".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn host_present_but_empty_counts_as_present() {
        // An empty Host header still counts as "present" for the authority
        // presence check. Value validation is handled by other rules.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("host", "")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn delete_with_absolute_uri_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "DELETE".into();
        tx.request.uri = "https://example.com/resource/42".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_uri_for_non_connect_is_path_violation() {
        // Empty URI means both :path and :authority are missing.
        // :path check fires first.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn root_path_with_query_and_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/?q=search".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The method token is case-sensitive, and the fold this replaced
    /// *suppressed* both findings: a lowercase `connect` took the tunnel branch
    /// and skipped the `:path` requirement, and a lowercase `options` was handed
    /// the asterisk. The twin had settled it the same way one conversion
    /// earlier.
    #[test]
    fn a_lowercase_connect_is_not_connect() {
        let message = judge("connect", "example.com:443").expect("reported");
        assert!(message.contains(":path"), "{message}");
    }

    #[rstest]
    #[case("options")]
    #[case("Options")]
    fn the_asterisk_belongs_to_options_written_that_way(#[case] method: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = method.into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("reported");
        assert!(v.message.contains("Asterisk"), "{}", v.message);
        assert!(v.message.contains(method), "{}", v.message);
    }

    #[test]
    fn absolute_uri_with_port_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com:8443/path".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn informational_response_100_is_ok() {
        // 1xx informational responses are valid (RFC 9114 §4.1).
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(100, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_returns_correct_value() {
        let rule = Http3PseudoHeadersValid;
        assert_eq!(rule.id(), "http3_pseudo_headers_valid");
    }

    #[test]
    fn connect_with_valid_response_is_ok() {
        // Validates response :status check runs after CONNECT request passes.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_with_invalid_response_status_is_not_this_rules_finding() {
        // A valid CONNECT request whose response carries an out-of-range status.
        // The request is what this rule reads, and it is well formed; the status is
        // `status_code_valid_range`'s finding on every version.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction_with_response(0, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn whitespace_only_uri_non_connect_is_path_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "   ".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn both_authority_and_host_present_is_ok() {
        // When both :authority (via absolute URI) and Host are present, no violation.
        // Value consistency is checked by host_and_authority_consistent,
        // which reads the same pair over both versions that carry an :authority.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn put_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "PUT".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn patch_origin_form_without_host_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "PATCH".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }
}
