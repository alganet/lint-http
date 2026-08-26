// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, list_members, shown_in_finding};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct Status405AllowValid;

impl Status405AllowValid {
    /// Whether this `Allow` field value names `method` among the methods the
    /// target resource is advertised as supporting.
    ///
    /// **A membership test, not the `#token` walk five rules in this tree share.**
    /// Two of that walk's decisions are here, because they are the two that decide
    /// *"is this member that method"*: the split, and the `OWS` trim around each
    /// member. The two that make it a grammar check are not — whether a member is
    /// empty and whether it derives from a `token` are
    /// `message_allow_header_method_tokens`' findings, since that rule owns this
    /// field's grammar. This one only asks whether some member is the string the
    /// method is, which is why the caller has to keep an empty method away from it:
    /// an ill-formed list holding an empty member would otherwise match one.
    ///
    /// Splitting on every comma finds exactly the members the list construct wrote:
    /// the comma is one of the delimiters a `token` excludes, and this field embeds
    /// no `quoted-string` for one to hide inside.
    ///
    /// **`list_members` is the walk, and the argument for writing it out here died
    /// when that helper stopped trimming Unicode whitespace.** This comment used to
    /// say no list helper answered the question: `parse_list_header` used `str::trim`,
    /// wrong for a value read one `char` per octet where %xA0 is `obs-text` and not
    /// whitespace at all, and `is_nominated_by_connection` folds case because what it
    /// looks for is a field name. The first half is no longer true — the two walks
    /// were one walk with one wrong line — and the fourth decision `list_members`
    /// makes, dropping an empty member, is one this question cannot see anyway: the
    /// caller keeps an empty method away, and a non-empty method equals no empty
    /// member.
    ///
    /// The comparison is exact rather than case-folding, and the sentence below is
    /// why: two spellings of a name in two cases are two methods, so a 405 answering
    /// `get` while advertising `GET` contradicts nothing. Case is the one decision
    /// the shared walk leaves to its caller, which is why this stays a function
    /// rather than becoming a call.
    ///
    /// cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
    /// cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
    fn advertises(value: &str, method: &str) -> bool {
        list_members(value).any(|member| member == method)
    }
}

impl Rule for Status405AllowValid {
    fn id(&self) -> &'static str {
        "status_405_allow_valid"
    }

    /// The requirement is on a response, so a capture whose upstream never answered
    /// has nothing to measure and `Server` is the scope that skips exactly those.
    ///
    /// Its subject is an origin server, and what this proxy captured is whatever
    /// answered — which the cited sentence makes the same thing for a gateway, the
    /// intermediary a 405 most often comes from. A forward proxy generating a 405 of
    /// its own is not an origin server for that response and is measured anyway,
    /// because no field of a message records which party wrote it.
    ///
    /// cite(RFC 9110 § 3.7): "All HTTP requirements applicable to an origin server also apply to the outbound communication of a gateway."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;

        // The status is the whole antecedent of both findings: the field is a MAY on
        // every other response, so a 200 carrying no `Allow` is a server taking the
        // licence rather than a defect. The status is one integer comparison and
        // `parse_rule_config` is several map probes plus a hash over the rule id, so
        // only a response this rule could report pays for the configuration.
        //
        // No version gate. The sentence defining this status names the request-line,
        // which only an HTTP/1.x message has — it is quoted below, where it decides
        // the second finding — but the status code it defines is the
        // version-independent document's, and the other two versions carry the same
        // method in a `:method` pseudo-header.
        //
        // cite(RFC 9110 § 10.2.1): "An origin server MUST generate an Allow header field in a 405 (Method Not Allowed) response and MAY do so in any other response."
        if resp.status != 405 {
            return None;
        }

        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        // One field section is one value however many lines carry it, and the join
        // is over the octets: a value carrying `obs-text` is a value that is there,
        // and reading it through a UTF-8 decode would fold the whole field into "no
        // such field here" and report a server that sent one.
        let Some(advertised) = combined_field_value_as_written(&resp.headers, "allow") else {
            // What the MUST asks for first is the field, and a field whose value is
            // empty is still the field: § 10.2.1 gives that value a meaning and
            // names this response as where it is likeliest to be read, so `Allow:`
            // on a 405 is a resource answering "none". Only a header section with no
            // `Allow` line at all reaches here.
            //
            // A trailer field does not answer it. § 15.5.6 asks for a header field,
            // and § 6.5.1 forbids a trailer field unless the field's own definition
            // permits one, which § 10.2.1 does not. Where the capture kept a trailer
            // section holding the name, the finding says so: a server that wrote it
            // there has a different thing to fix from one that wrote nothing.
            //
            // cite(RFC 9110 § 10.2.1): "An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration."
            // cite(RFC 9110 § 15.5.6): "The origin server MUST generate an Allow header field in a 405 response containing a list of the target resource's currently supported methods."
            // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
            let in_trailer_section = resp
                .trailers
                .as_ref()
                .is_some_and(|trailers| trailers.contains_key("allow"));

            return violation(format!(
                "405 Method Not Allowed with no Allow header field. An origin server must generate one in this response, listing the methods the target resource currently supports; a resource that supports none says so with an empty field value, which is not the same as leaving the field out{}",
                if in_trailer_section {
                    ". This response's trailer section carries an Allow, and a trailer field does not answer a requirement on the header section"
                } else {
                    ""
                }
            ));
        };

        // The MUST does not stop at the field's name. Its object clause is the first
        // sentence below — the field is to hold *the target resource's currently
        // supported methods* — and the second says what the status this response
        // carries states about the method it answers. One message makes both
        // statements, about one target resource, so a 405 whose `Allow` names the
        // refused method contradicts itself and a recipient cannot act on it.
        //
        // What the two sentences after them do *not* license is any wider
        // comparison: which methods the list should have held instead is the origin
        // server's answer at the time of each request, and it moves under the
        // resource, so no other captured message disagrees with this one. The
        // disagreement reported here is the one internal to a single exchange.
        //
        // An empty method is compared against nothing: `method = token` is `1*tchar`
        // and derives no empty string, so a capture holding one names nothing for a
        // member to agree with, and an empty member of this list would then match
        // it. `request_method_token_valid` reports that value.
        //
        // cite(RFC 9110 § 15.5.6): "The origin server MUST generate an Allow header field in a 405 response containing a list of the target resource's currently supported methods."
        // cite(RFC 9110 § 15.5.6): "The 405 (Method Not Allowed) status code indicates that the method received in the request-line is known by the origin server but not supported by the target resource."
        // cite(RFC 9110 § 10.2.1): "The "Allow" header field lists the set of methods advertised as supported by the target resource."
        // cite(RFC 9110 § 10.2.1): "The actual set of allowed methods is defined by the origin server at the time of each request."
        // cite(RFC 9110 § 9.1): "However, the set of allowed methods can change dynamically."
        if !tx.request.method.is_empty() && Self::advertises(&advertised, &tx.request.method) {
            // The value is quoted as the section's *combined* value and the message
            // says so, because where two field lines carried it the commas between
            // them are the join's rather than anything a sender wrote.
            return violation(format!(
                "405 Method Not Allowed answering the method '{}', whose Allow header field advertises that same method: the status says the target resource does not support it and the field says it does. The section's field lines combine to '{}'",
                shown_in_finding(&tx.request.method),
                shown_in_finding(&advertised)
            ));
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports two things about a `405 (Method Not Allowed)` response: that it carries no `Allow` header field, and that the `Allow` it does carry names the very method the status refuses.\n\n**The requirement, and where the licence for every other response comes from.** RFC 9110 §15.5.6: \"The origin server MUST generate an Allow header field in a 405 response containing a list of the target resource's currently supported methods.\" §10.2.1 states the same requirement with the clause the other lacks — \"An origin server MUST generate an Allow header field in a 405 (Method Not Allowed) response and MAY do so in any other response\" — which is why no other status is asked for the field here.\n\n**An empty value is an answer, not an omission.** §10.2.1: \"An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration.\" The section names this response by name, so `Allow:` on a 405 satisfies the MUST, and a whitespace-only value is the same value (§5.5). Presence is the whole of the first finding: whether the members are `method` tokens is `message_allow_header_method_tokens`'s question, and the value is read as octets rather than through a UTF-8 decode, so a field carrying `obs-text` counts as a field that is there.\n\n**The second finding is the clause after \"containing\".** The status says \"the method received in the request-line is known by the origin server but not supported by the target resource\" (§15.5.6), and the field \"lists the set of methods advertised as supported by the target resource\" (§10.2.1). A 405 answering `POST` whose `Allow` names `POST` says both at once about one resource at one instant — the shape a router or a preflight handler produces when it answers 405 with the resource's full method list. Methods are matched exactly, because §9.1 says \"The method token is case-sensitive\": a 405 answering `get` while advertising `GET` is two methods and not this finding. A request whose method is empty is compared against nothing, since `method = token` derives no empty string; `request_method_token_valid` reports that value.\n\n**Not reported: which methods the list should have held.** §10.2.1: \"The actual set of allowed methods is defined by the origin server at the time of each request\", and §9.1 adds \"However, the set of allowed methods can change dynamically\" — so no captured message disagrees with an `Allow` list by holding a different one, and the only disagreement this rule can see is the one internal to a single exchange.\n\n**Not reported: that a 405 refused `GET` or `HEAD` at all.** §9.1's \"All general-purpose servers MUST support the methods GET and HEAD\" is addressed to the server, and the same section leaves the resource its own answer: \"Once defined, a standardized method ought to have the same semantics when applied to any resource, though each resource determines for itself whether those semantics are implemented or allowed.\" So a resource that answers `GET` with a 405 is not reported for the status — though a 405 refusing `GET` while advertising `GET` is the finding above, like any other method.\n\n**Not reported: a 405 where §9.1 asks for a 501.** \"An origin server that receives a request method that is unrecognized or not implemented SHOULD respond with the 501 (Not Implemented) status code\", against 405 for one \"that is recognized and implemented, but not allowed for the target resource\". Telling those apart means knowing which method names exist, which is a registry question: `request_method_token_valid` carries the required `registered_methods` array that asks it, and making that array required here would silence this rule's MUST on every deployment that has not written one.\n\n**A trailer does not answer it.** The requirement is on a header field, and §6.5.1 forbids a trailer field unless the field's own definition permits one, which §10.2.1 does not. A 405 carrying `Allow` only in its trailer section is reported here as carrying none, and the finding says the trailer was seen — which is the whole of what this rule says about that placement. Reporting the placement itself belongs to `message_trailer_fields_validity`, the rule that applies §6.5.1 to field names; its list does not name `allow` today, so nothing in the catalogue reports an `Allow` for being in a trailer section, and that is an open question there rather than one this rule answers from outside.\n\n**Scope and version.** Every HTTP version is measured: §15.5.6 says the method was \"received in the request-line\", which only an HTTP/1.x message has, but the status code it defines is the version-independent document's and HTTP/2 and HTTP/3 carry the same method in a `:method` pseudo-header. The requirement's subject is an origin server and a capture holds whatever answered — §3.7 carries every origin-server requirement onto \"the outbound communication of a gateway\", so a reverse proxy's 405 is measured on the same terms. A forward proxy that generates a 405 of its own is not an origin server for that response and is measured anyway, because no field of a message records which party wrote it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.6",
                note: "The status code and its MUST — including the clause after \"containing\", which asks the field to hold the methods the target resource supports and so contradicts a list naming the method this response refuses",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1",
                note: "The field: the same MUST worded with the MAY that licenses silence on every other response, the sentence giving an empty value a meaning in this exact response, and the set of allowed methods being the origin server's at the time of each request",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "The method token is case-sensitive, which is why the request's method is matched against the members exactly; also the 405-versus-501 division and the sentence leaving each resource to decide which methods it allows",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-3.7",
                note: "Why a requirement addressed to an origin server is measured against whatever answered: every one of them applies to a gateway's outbound communication",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "A field value excludes the whitespace around it, which is why a value that is only whitespace is the empty value and answers the requirement — and why the value is read as octets rather than through a UTF-8 decode, since `obs-text` is an octet field content admits",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "The delimiter set that makes splitting this field on every comma exact: a `method` is a `token`, which admits no comma, and the field embeds no `quoted-string` for one to hide inside",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1",
                note: "Why an `Allow` in the trailer section does not answer this requirement — a trailer field needs its own definition's permission, and the field's definition gives none",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The field is there and lists methods the refused one is not among"),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nContent-Type: text/plain\nAllow: GET, HEAD",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "§10.2.1's temporarily disabled resource — an empty value is what \"no methods\" looks like",
                ),
                snippet: "DELETE /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nAllow:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "Two field lines in one section are one list, and the refused method is a member of it",
                ),
                snippet: "PUT /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nAllow: GET\nAllow: PUT",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "The method token is case-sensitive, so `get` and `GET` are two methods and the response contradicts nothing",
                ),
                snippet: "get /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nAllow: GET, HEAD",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Every other response MAY carry the field, so its absence says nothing"),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The MUST's own subject — a 405 carrying no Allow at all"),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "The clause after \"containing\" — the list names the method the status refuses",
                ),
                snippet: "POST /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 405 Method Not Allowed\nAllow: GET, POST, HEAD",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status405AllowValid;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_transaction::ResponseInfo;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    /// Run the rule over a transaction whose request carries `method` and whose
    /// response carries `status` plus the given response field lines.
    ///
    /// The lines are appended rather than inserted, because several field lines in
    /// one section are one value and a single-line helper cannot reach that case;
    /// they are raw octets, because a value carrying `obs-text` is not a string any
    /// Rust source file can stand in for.
    fn check(method: &str, status: u16, lines: &[(&str, &[u8])]) -> Option<Violation> {
        check_with_trailers(method, status, lines, &[])
    }

    /// The same, with a trailer section — the placement § 6.5.1 does not permit for
    /// this field and which the finding names when it finds one.
    fn check_with_trailers(
        method: &str,
        status: u16,
        lines: &[(&str, &[u8])],
        trailer_lines: &[(&str, &[u8])],
    ) -> Option<Violation> {
        let rule = Status405AllowValid;
        let mut tx = make_test_transaction();
        tx.request.method = method.into();

        let build = |pairs: &[(&str, &[u8])]| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.append(
                    hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_bytes(value).unwrap(),
                );
            }
            headers
        };

        tx.response = Some(ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: build(lines),
            body_length: None,
            trailers: if trailer_lines.is_empty() {
                None
            } else {
                Some(build(trailer_lines))
            },
        });

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("POST", 405, &[][..], true)]
    #[case("POST", 405, &[("allow", b"GET, HEAD".as_slice())][..], false)]
    #[case("POST", 200, &[][..], false)]
    #[case("POST", 404, &[][..], false)]
    // The status is the antecedent of both findings, so a 200 advertising the
    // method that was used is a server taking § 10.2.1's MAY.
    #[case("POST", 200, &[("allow", b"GET, POST".as_slice())][..], false)]
    fn a_405_is_asked_for_the_field_and_no_other_response_is(
        #[case] method: &str,
        #[case] status: u16,
        #[case] lines: &[(&str, &[u8])],
        #[case] expect_violation: bool,
    ) {
        let violation = check(method, status, lines);
        assert_eq!(
            violation.is_some(),
            expect_violation,
            "{} -> {} {:?} — {:?}",
            method,
            status,
            lines,
            violation
        );
    }

    /// § 10.2.1 gives the empty value a meaning and names this response as where it
    /// arrives, so the field being present is the whole of the first finding. A
    /// value that is only whitespace is the same value (§ 5.5).
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t  ")]
    fn an_empty_field_value_answers_the_requirement(#[case] value: &[u8]) {
        assert!(
            check("POST", 405, &[("allow", value)]).is_none(),
            "an empty Allow field value is a resource advertising no methods"
        );
    }

    /// The field is read as octets. Through `to_str` a value carrying `obs-text`
    /// answers `None`, which would fold "this field is unreadable" into "this
    /// response has no Allow" and report a server that sent one.
    ///
    /// The second assertion is the one that proves the octets reached the
    /// comparison rather than merely stopping the absence finding: the value is one
    /// `char` per octet, so %xC9 in the member and %xC9 in the method are the same
    /// string and the contradiction is found.
    #[test]
    fn a_value_carrying_obs_text_is_still_a_field_that_is_there() {
        assert!(check("POST", 405, &[("allow", b"G\xC9T")]).is_none());

        let violation = check("G\u{C9}T", 405, &[("allow", b"GET, G\xC9T")])
            .expect("the member and the method are the same octets");
        assert!(
            violation.message.contains("advertises that same method"),
            "{}",
            violation.message
        );
    }

    /// The clause after "containing": the status says the target resource does not
    /// support this method and the field says it does.
    #[rstest]
    #[case("POST", b"GET, POST, HEAD")]
    #[case("POST", b"POST")]
    #[case("DELETE", b"GET,DELETE")]
    // The member is `OWS`-trimmed before the comparison, which is what the list
    // construct prints around its commas.
    #[case("PATCH", b"GET,   PATCH   ")]
    // An empty member contributes no method, and the members beside it are still
    // read.
    #[case("PUT", b"GET,,PUT")]
    fn a_405_advertising_the_method_it_refuses_is_reported(
        #[case] method: &str,
        #[case] allow: &[u8],
    ) {
        let violation =
            check(method, 405, &[("allow", allow)]).expect("the response states both at once");
        assert!(
            violation.message.contains("advertises that same method"),
            "{}",
            violation.message
        );
        assert!(
            violation.message.contains(&format!("'{}'", method)),
            "{}",
            violation.message
        );
    }

    /// § 9.1: the method token is case-sensitive. A 405 answering `get` while
    /// advertising `GET` refuses one method and advertises another, which is not a
    /// contradiction — folding the case here would manufacture one.
    #[rstest]
    #[case("get", b"GET, HEAD")]
    #[case("GET", b"get, HEAD")]
    #[case("POST", b"post")]
    fn a_name_in_another_case_is_another_method(#[case] method: &str, #[case] allow: &[u8]) {
        assert!(check(method, 405, &[("allow", allow)]).is_none());
    }

    /// A method that derives from no `token` names nothing for a member to agree
    /// with — and the empty member an ill-formed list can hold is exactly what it
    /// would match, which is what makes the guard load-bearing rather than
    /// defensive. A list with no empty member would pass either way, so this is the
    /// case worth writing.
    #[test]
    fn an_empty_method_is_compared_against_nothing() {
        assert!(check("", 405, &[("allow", b"GET,,HEAD")]).is_none());
    }

    /// One field section is one value however many lines carry it, and the finding
    /// says so: the comma between two lines' values is the join's, not something an
    /// operator can grep the capture for.
    #[test]
    fn field_lines_in_one_section_are_one_list() {
        assert!(check("PUT", 405, &[("allow", b"GET"), ("allow", b"HEAD")]).is_none());

        let violation = check("PUT", 405, &[("allow", b"GET"), ("allow", b"PUT")])
            .expect("the second line's member is a member of the same list");
        assert!(
            violation
                .message
                .contains("field lines combine to 'GET,PUT'"),
            "{}",
            violation.message
        );
    }

    /// § 15.5.6 asks for a header field and § 6.5.1 admits a trailer field only
    /// where the field's own definition permits one, which § 10.2.1 does not. The
    /// requirement is unmet either way; the finding distinguishes the two servers.
    #[test]
    fn a_trailer_does_not_answer_a_requirement_on_the_header_section() {
        let violation = check_with_trailers("POST", 405, &[], &[("allow", b"GET, HEAD")])
            .expect("a trailer field is not a header field");
        assert!(
            violation
                .message
                .contains("trailer section carries an Allow"),
            "{}",
            violation.message
        );

        let plain = check("POST", 405, &[]).expect("no Allow anywhere is the same requirement");
        assert!(
            !plain.message.contains("trailer"),
            "the clause is only written where a trailer was seen: {}",
            plain.message
        );
    }

    /// A response the rule reports is one whose value it prints, and a value read
    /// back from a capture can hold octets that corrupt a finding rather than appear
    /// in it. HTAB is `OWS` inside the value and reaches the message through the
    /// member that is not trimmed away.
    #[test]
    fn a_printed_value_cannot_corrupt_the_finding() {
        let violation = check("PO\tST", 405, &[("allow", b"GET, PO\tST")])
            .expect("the member and the method are the same octets");
        assert!(!violation.message.contains('\t'), "{}", violation.message);
        assert!(
            violation.message.contains("'PO\\tST'"),
            "{}",
            violation.message
        );
    }

    #[test]
    fn scope_is_server_because_the_requirement_is_on_a_response() {
        assert_eq!(Status405AllowValid.scope(), crate::rules::RuleScope::Server);
    }

    /// Every published example is a case this rule decides the way its label claims.
    /// The snippet is a request half, a blank line, and a response half.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::Compliance;

        let mut asserted_a_finding = false;

        for example in Status405AllowValid.examples() {
            let (request, response) = example
                .snippet
                .split_once("\n\n")
                .expect("every example writes the request half that names the method");

            let method = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().next())
                .expect("a request line names a method");

            let mut lines = response.lines();
            let status: u16 = lines
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .expect("a status line names a status code");

            // Split on the colon rather than on `": "`, or a field line written with
            // an empty value — the one §10.2.1 gives a meaning to — is dropped and
            // the example silently becomes a response with no `Allow` at all.
            let fields: Vec<(String, Vec<u8>)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(n, v)| {
                    (
                        n.to_ascii_lowercase(),
                        v.strip_prefix(' ').unwrap_or(v).as_bytes().to_vec(),
                    )
                })
                .collect();
            let borrowed: Vec<(&str, &[u8])> = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_slice()))
                .collect();

            let violation = check(method, status, &borrowed);
            match example.compliance {
                Compliance::Compliant => assert!(
                    violation.is_none(),
                    "compliant example reported: {} -> {:?}",
                    example.snippet,
                    violation
                ),
                Compliance::NonCompliant => {
                    assert!(
                        violation.is_some(),
                        "non-compliant example not reported: {}",
                        example.snippet
                    );
                    asserted_a_finding = true;
                }
            }
        }

        assert!(
            asserted_a_finding,
            "the guard is vacuous unless at least one example produces a finding"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = Status405AllowValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules
            .insert("status_405_allow_valid".into(), toml::Value::Table(table));

        rule.validate(&cfg)?;
        Ok(())
    }
}
