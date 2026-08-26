// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_octet, sender_list_members, shown_in_finding,
    trim_ows,
};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct AllowHeaderMethodTokensValid;

impl AllowHeaderMethodTokensValid {
    /// One field section's `Allow` value, measured against the production the
    /// section that defines the field prints.
    ///
    /// `section` names the half of the exchange the value was read from and goes
    /// into every finding, and the cited sentence is why that is worth the words:
    /// the field is grouped with the fields a *response* carries, so a defect found
    /// in a request is said out loud rather than reported as though a server had
    /// written it.
    ///
    /// The production this walks is `Allow = #method`, which is fifteen characters
    /// where § 10.2.1 prints it and so below what a fragment can be; the collected
    /// grammar's sender-expanded copy is quoted instead, at the branch it decides.
    ///
    /// `value` is the section's combined field value, one `char` per octet — the
    /// invariant the octet cast below depends on. Reading it here rather than
    /// taking a `&HeaderMap`, as the two sibling list rules do, is what lets the
    /// caller gate on the field's presence before it reads any configuration.
    ///
    /// cite(RFC 9110 § 10.2.1): "The "Allow" header field lists the set of methods advertised as supported by the target resource."
    /// cite(RFC 9110 § 10.2.1): "The purpose of this field is strictly to inform the recipient of valid request methods associated with the resource."
    /// cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
    fn check_field_section(
        &self,
        value: &str,
        section: &str,
        config: &crate::rules::RuleConfig,
    ) -> Option<Violation> {
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        // The field's own production, in the form the collected grammar gives a
        // sender, and the two things it says about emptiness. The outer `[ ]` is why
        // an `Allow:` carrying nothing is not reported: the field is `#method` and
        // not `1#method`, so a list of no methods is a list this production
        // generates. Here that is not merely tolerated — § 10.2.1 states what such a
        // value tells the recipient and names the response it is likeliest to arrive
        // in, so reporting it contradicted the section the rule is named for. What
        // the production never generates is a *member* that is empty: every position
        // in it holds a `method`, which is `token`, which is `1*tchar`.
        //
        // The trim here is not the trim inside the loop and does not rest on the same
        // sentence. A member is surrounded by the `OWS` the list construct prints
        // around its commas; the *value* is not, and what licenses trimming it is
        // § 5.5's MUST on the parser — so `Allow:   ` is a value of no methods rather
        // than a value holding one empty member.
        //
        // cite(RFC 9110 § A, label: Allow grammar, sender-expanded): "Allow = [ method *( OWS "," OWS method ) ]"
        // cite(RFC 9110 § 10.2.1): "An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration."
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        if trim_ows(value).is_empty() {
            return None;
        }

        let mut saw_an_empty_element = false;

        // Splitting on every comma finds exactly the members the list construct
        // wrote, because a `method` can hold no comma: the comma is one of the
        // delimiters a `token` excludes, and this field embeds no `quoted-string`
        // for one to hide inside. The readers in this tree that have to respect
        // quoting are answering a different field's grammar, not being more careful
        // about this one.
        //
        // cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
        for member in sender_list_members(value) {
            if member.is_empty() {
                // Reported after the members that are present, and reported as the
                // list's defect rather than the element's: there is no such thing as
                // an empty `method`, so what the sender generated is a member that
                // contributes nothing to the list. § 5.6.1.2 has the *recipient*
                // parse and ignore these, which is the other party's requirement and
                // would erase this one — so the lenient reader is not used here.
                //
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present.  A recipient MUST parse and ignore a reasonable number of empty list elements: enough to handle common mistakes by senders that merge values, but not so much that they could be used as a denial-of-service mechanism."
                saw_an_empty_element = true;
                continue;
            }

            // Every position in the list holds a `method`, and a `method` is a
            // `token`; `tchar` is transcribed once, on the helper that answers this.
            // The empty member cannot reach here, and that matters: a character scan
            // answers `None` for the empty string because it finds no character to
            // object to, so the `1*` floor is the branch above rather than this one.
            //
            // An octet at or above %x80 is `obs-text`, which `field-content` admits
            // and `token` does not; the value carries one `char` per octet, so such
            // an octet arrives here as a `char` outside the `tchar` set and is
            // reported as the member's defect rather than folding the whole field
            // into "this message has no `Allow`".
            //
            // The production is quoted from the collected grammar, which brings its
            // neighbour along: where § 9.1 prints it, `method = token` stands alone
            // between two paragraphs and is fourteen characters, below what a
            // fragment can be.
            // cite(RFC 9110 § A): "method = token minute = 2DIGIT"
            if let Some(ch) = crate::helpers::token::find_invalid_token_char(member) {
                // The two halves of this message are rendered by the two helpers that
                // own them, and they answer differently on purpose. The octet that
                // failed the test is *named*: one `char` per octet means `ch` is
                // always in %x00-FF, and the octets that fail a `tchar` test are very
                // often the ones that print as nothing, so `0xC9` is what the finding
                // can be read back from. The member is *escaped for display*, which
                // leaves a printable code point alone — so %xC9 still shows in it as
                // `É`, legibly and wrongly as to encoding, which is exactly why the
                // authoritative half is the named octet beside it.
                //
                // The two sibling rules walking a `#token` list render both halves a
                // third and a fourth way — one escapes the character and prints the
                // member raw, the other prints both raw. Recorded rather than
                // harmonised: converting them changes what their findings say, which
                // is their own audits' work.
                debug_assert!(
                    (ch as u32) <= 0xFF,
                    "the value is one `char` per octet; a wider `char` would truncate into a different octet"
                );
                return violation(format!(
                    "Allow in the {} header section: member '{}' contains {}, which is not a `tchar`, so it derives from no `token` and therefore from no `method`",
                    section,
                    shown_in_finding(member),
                    describe_octet(ch as u8)
                ));
            }
        }

        if saw_an_empty_element {
            // The value is quoted as the section's *combined* value and the message
            // says so, because for the case this branch exists to catch it is not a
            // string the sender wrote: an `Allow:` line beside an `Allow: GET` line
            // combines to `GET,`, whose comma is the join's. An operator grepping a
            // capture for the quoted text would otherwise find nothing.
            return violation(format!(
                "Allow in the {} header section holds an empty list element; the section's field lines combine to '{}'. A resource that allows no methods says so with an empty field value; a comma with nothing beside it says nothing",
                section,
                shown_in_finding(value)
            ));
        }

        None
    }
}

impl Rule for AllowHeaderMethodTokensValid {
    fn id(&self) -> &'static str {
        "allow_header_method_tokens_valid"
    }

    /// The grammar is the whole of this rule and § 2.2 addresses whoever generated
    /// the element, so both halves of the exchange are read and neither needs the
    /// other to be present. `Both` is the scope that survives into the request-only
    /// dispatch; `Server` would skip exactly the captures where the request is all
    /// there is.
    ///
    /// cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // One field section is one list however many lines carry it, so the lines are
        // joined before the members are counted: an `Allow:` written as a second line
        // is an empty *member* of the joined value, while the same line written alone
        // is the empty list § 10.2.1 gives a meaning to. Reading the lines one at a
        // time answered both of those backwards. The join, and the sentence licensing
        // it, live on the helper.
        //
        // Where the field belongs is § 10.2's answer, quoted where the section name
        // is put into a finding, and it is not a requirement: an `Allow` in a request
        // is unusual, nothing forbids it, and this rule does not report it for being
        // there — it measures whatever value it finds.
        //
        // The two reads are the two *header* sections. A response's trailer section is
        // not read: whether a field may arrive as a trailer at all is § 6.5.1's
        // question, which is asked of every field name by
        // `trailer_fields_valid` rather than field by field here, and
        // `description()` says so rather than leaving the silence to be read as a
        // verdict.
        //
        // Each read is one `HeaderMap` probe, and a message carrying no `Allow` at all
        // is the overwhelming majority of traffic; `parse_rule_config` is several map
        // probes plus a hash over the rule id, so only a message that carries the
        // field pays for it.
        let request = combined_field_value_as_written(&tx.request.headers, "allow");
        let response = tx
            .response
            .as_ref()
            .and_then(|resp| combined_field_value_as_written(&resp.headers, "allow"));

        if request.is_none() && response.is_none() {
            return None;
        }

        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        if let Some(value) = &request {
            if let Some(v) = self.check_field_section(value, "request", &config) {
                return Some(v);
            }
        }

        if let Some(value) = &response {
            if let Some(v) = self.check_field_section(value, "response", &config) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Allow Header Method Tokens")
    }

    fn description(&self) -> &'static str {
        "Validates the `Allow` header field's own value — the set of methods a resource advertises as supported.\n\nThe field is `Allow = [ method *( OWS \",\" OWS method ) ]` (RFC 9110 §A), and a `method` is a `token` (§9.1). So every member must be `1*tchar`: `Allow: GET POST` names one member and no method, because SP is not a `tchar`, and `Allow: PO@T` fails on a delimiter (§5.6.2). No member may be empty — `Allow: GET,,POST` and `Allow: GET,` are lists a sender MUST NOT generate (§5.6.1.1).\n\n**An empty value is not an empty member, and this rule used to report it.** The production's outer brackets make a list of no methods a list, and §10.2.1 goes further than tolerating it: \"An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration.\" So `Allow:` is a resource saying something, in the response the section names — and a rule reporting it contradicted the sentence it was written from. `Allow:   ` is the same value: §5.5 excludes whitespace around a field value before it is evaluated.\n\nWhere the field appears on several lines in one section, the lines are one value (§5.2) — so `Allow: GET` followed by `Allow:` is a list whose second member is empty, which *is* reported, while a lone `Allow:` is not. A value carrying an octet outside US-ASCII is measured rather than skipped: `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a token, which is what is wrong with it. The finding names that octet — `0xC9`, not the code point some encoding would read it as — while the member beside it is shown escaped for legibility, so the two halves of the message are read differently on purpose.\n\n**Not reported: a method name written in an unexpected case.** `Allow: get, POST` advertises a method whose name is `get`, and the method token is case-sensitive (§9.1) — but nothing in §10.2.1 restricts which names a resource may advertise, and separating a mis-cased standard name from a deployment's own lowercase extension needs the registry. `request_method_token_valid` is the rule that asks that question, of a request's method, and it carries the required `registered_methods` array the question needs; making that array required here would silence this grammar check on every deployment that has not written one.\n\n**Not reported: whether the advertised methods are the right ones.** §10.2.1 says \"The actual set of allowed methods is defined by the origin server at the time of each request\", so no capture disagrees with an `Allow` list by holding a different one. A duplicated member is not reported either — the section calls the value a set in prose, and the production repeats `method` without restriction.\n\n**Not checked at all: \"A proxy MUST NOT modify the Allow header field\" (§10.2.1).** A capture records one message as this proxy saw it, not the same message before and after a hop, so the two values that requirement compares are never both present. It is left here as a decline rather than as an unremarked gap.\n\nScope: this rule reads header sections — a request's and a response's — and measures the value whatever protocol version carried it, because the production is written in the version-independent document. §10.2 places the field among response context fields; an `Allow` in a request is unusual rather than forbidden, so it is measured and not reported for being there. **A trailer section is not read.** Whether a field name may arrive as a trailer at all is §6.5.1's question, and it is asked of every name at once by `trailer_fields_valid` rather than field by field here — so an `Allow` in a trailer draws whatever that rule says about it and nothing from this one. Whether a 405 response carries the field at all is §15.5.6's question and `status_405_allow_valid`'s; whether an OPTIONS response carries it is `options_method_capabilities`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1",
                note: "The field itself: its grammar, what the set of methods means, and the sentence that gives an empty field value a meaning rather than making it a defect",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("A"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
                note: "The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not, and where `method = token` is quotable",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "The sender's half of the list construct — the empty-member finding. The recipient's half (§5.6.1.2, parse and ignore them) is a different party's requirement, which is why the lenient list reader is not used here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "`token = 1*tchar`, transcribed once in `helpers::token::is_tchar`, and the delimiter set that makes splitting this field on every comma exact",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "A field value excludes the whitespace around it, so a value that is only whitespace is the empty value — and `obs-text` is an octet field content admits, which is why the value is read as octets rather than through a UTF-8 decode",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sentence that makes a value outside its own grammar a violation, and the reason both halves of the exchange are measured: it addresses whoever generated the element",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The section's own example of use"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET, HEAD, PUT",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "A list of no methods is a list — the resource allows none, which §10.2.1 puts in exactly this response",
                ),
                snippet: "HTTP/1.1 405 Method Not Allowed\nAllow:",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An extension method is a token like any other"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET, X-CUSTOM-METHOD",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Two field lines in one section are one list"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET\nAllow: POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty member — the list construct's sender requirement"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET, , POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A trailing comma is an empty member too"),
                snippet: "HTTP/1.1 405 Method Not Allowed\nAllow: GET,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty line beside a non-empty one is an empty member of the joined list"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET\nAllow:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("SP is not a `tchar`, so this is one member and no method"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A delimiter inside a member"),
                snippet: "HTTP/1.1 200 OK\nAllow: GET, PO@T",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AllowHeaderMethodTokensValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    /// Build a transaction carrying the given `Allow` field *lines* in one section
    /// and run the rule over it.
    ///
    /// The lines are appended rather than inserted, because several field lines in
    /// one section are what the joining is about and a single-line helper cannot
    /// reach the case.
    fn check_allow(lines: &[&str], is_response: bool) -> Option<Violation> {
        check_allow_bytes(
            &lines.iter().map(|l| l.as_bytes()).collect::<Vec<_>>(),
            is_response,
        )
    }

    /// The same, over raw octets — the only way to write a value carrying
    /// `obs-text`, which no `&str` in a Rust source file can stand in for.
    fn check_allow_bytes(lines: &[&[u8]], is_response: bool) -> Option<Violation> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;

        let rule = AllowHeaderMethodTokensValid;
        let mut tx = make_test_transaction();

        if is_response && tx.response.is_none() {
            tx.response = Some(ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: HeaderMap::new(),

                body_length: None,
                trailers: None,
            });
        }

        let headers = if is_response {
            &mut tx.response.as_mut().unwrap().headers
        } else {
            &mut tx.request.headers
        };

        for line in lines {
            headers.append(hyper::header::ALLOW, HeaderValue::from_bytes(line).unwrap());
        }

        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("GET", false, false)]
    #[case("GET, POST", false, false)]
    #[case("GET, POST, PUT, DELETE", false, false)]
    #[case("GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS", true, false)]
    #[case("GET,POST", false, false)]
    #[case("GET , POST", false, false)]
    #[case("CUSTOM-METHOD", true, false)]
    #[case("GET, , POST", false, true)]
    #[case("GET POST", false, true)]
    #[case("GET, PO@T", false, true)]
    // A name in another case is a `token`, and which names a resource may advertise
    // is not this rule's question.
    #[case("get, POST", false, false)]
    // Response header variants exercising the response branch.
    #[case("GET, , POST", true, true)]
    #[case("GET, PO@T", true, true)]
    fn allow_members_are_method_tokens(
        #[case] allow_value: &str,
        #[case] is_response: bool,
        #[case] expect_violation: bool,
    ) {
        let violation = check_allow(&[allow_value], is_response);

        assert_eq!(
            violation.is_some(),
            expect_violation,
            "Allow: {} — {:?}",
            allow_value,
            violation
        );
    }

    /// The whole value, empty: `Allow = #method` has no minimum, and § 10.2.1 says
    /// what such a value means rather than treating it as a defect. This rule used
    /// to report it, in the response the section names.
    #[rstest]
    #[case("")]
    #[case(" ")]
    #[case("\t  ")]
    fn an_empty_value_is_a_list_of_no_methods(#[case] value: &str) {
        assert!(
            check_allow(&[value], true).is_none(),
            "an empty Allow field value is how a resource advertises no methods"
        );
        assert!(check_allow(&[value], false).is_none());
    }

    /// The other side of the same sentence: an empty member is not an empty list.
    #[rstest]
    #[case("GET,")]
    #[case(",GET")]
    #[case("GET,,POST")]
    #[case(",")]
    fn an_empty_member_is_not_an_empty_list(#[case] value: &str) {
        let violation = check_allow(&[value], true).expect("empty list element is reported");
        assert!(
            violation.message.contains("empty list element"),
            "{}",
            violation.message
        );
    }

    /// One field section is one list however many lines carry it. Both directions
    /// of this were wrong when the lines were read separately: the empty second
    /// line went unreported as a member, and a lone empty line was reported as one.
    #[test]
    fn field_lines_in_one_section_are_one_list() {
        assert!(check_allow(&["GET", "POST"], true).is_none());

        let violation =
            check_allow(&["GET", ""], true).expect("an empty second line is an empty member");
        assert!(
            violation.message.contains("empty list element"),
            "{}",
            violation.message
        );
        // `GET,` is not a string either line carries; the comma is the join's, and
        // the finding says the lines were combined rather than quoting it as written.
        assert!(
            violation.message.contains("field lines combine to 'GET,'"),
            "{}",
            violation.message
        );

        assert!(
            check_allow(&[""], true).is_none(),
            "the same line on its own is the empty list"
        );
    }

    /// `obs-text` is an octet `field-content` admits and `token` does not. Reading
    /// the value through `to_str` turned the whole field into "no such field here"
    /// and dropped the finding; a method spelled with the raw %xC9 drew nothing from
    /// this rule at all.
    ///
    /// The two halves of the message are rendered by the two helpers that own them,
    /// and they answer differently on purpose: the *octet* that stopped the parse is
    /// named (`0xC9`), while the *member* is escaped for display and an escape leaves
    /// a printable code point alone. Asserting the member does not contain U+00C9
    /// would be asserting against `shown_in_finding`'s documented behaviour.
    #[test]
    fn obs_text_is_measured_rather_than_skipped() {
        let violation = check_allow_bytes(&[b"G\xC9T"], true).expect("obs-text is not a tchar");
        assert!(
            violation.message.contains("0xC9"),
            "the octet that failed the tchar test is named: {}",
            violation.message
        );
    }

    /// The finding names which half of the exchange carried the value, because the
    /// rule reads both and the field's definition places it in only one of them.
    #[test]
    fn findings_name_the_section_they_were_found_in() {
        let request = check_allow(&["GET, PO@T"], false).unwrap();
        assert!(
            request.message.contains("request header section"),
            "{}",
            request.message
        );

        let response = check_allow(&["GET, PO@T"], true).unwrap();
        assert!(
            response.message.contains("response header section"),
            "{}",
            response.message
        );
    }

    /// The member is reported with the octet named and the member escaped. Both
    /// renderers have a printable path and a non-printable one, and a test that only
    /// ever feeds them `@` and SP exercises neither: HTAB is the case that reaches
    /// both, and a `HeaderValue` admits it.
    #[test]
    fn a_member_that_is_no_token_names_the_octet() {
        let violation = check_allow(&["GET, PO@T"], true).unwrap();
        assert!(
            violation.message.contains("'PO@T'"),
            "{}",
            violation.message
        );
        assert!(violation.message.contains("'@'"), "{}", violation.message);

        let space = check_allow(&["GET POST"], true).unwrap();
        assert!(space.message.contains("'GET POST'"), "{}", space.message);

        // A member holding a control octet: the octet is named as `0x09` and the
        // member is escaped, so no raw HTAB reaches the finding to break the line it
        // is printed on.
        let htab = check_allow(&["GE\tT"], true).unwrap();
        assert!(htab.message.contains("0x09"), "{}", htab.message);
        assert!(htab.message.contains("'GE\\tT'"), "{}", htab.message);
        assert!(!htab.message.contains('\t'), "{}", htab.message);
    }

    #[test]
    fn no_allow_header_is_not_a_finding() {
        use crate::test_helpers::make_test_transaction;

        let rule = AllowHeaderMethodTokensValid;
        let tx = make_test_transaction();

        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn scope_is_both_because_either_party_can_write_the_field() {
        let rule = AllowHeaderMethodTokensValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// Every published example is a case this rule actually decides the way the
    /// label claims. A presence-shaped rule cannot catch its own stale example, and
    /// this one shipped an `Allow:` marked NonCompliant that §10.2.1 makes
    /// compliant.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::Compliance;

        let rule = AllowHeaderMethodTokensValid;
        let mut asserted_a_finding = false;

        for example in rule.examples() {
            let lines: Vec<&str> = example
                .snippet
                .lines()
                .filter_map(|l| l.strip_prefix("Allow:"))
                .map(|v| v.strip_prefix(' ').unwrap_or(v))
                .collect();
            assert!(
                !lines.is_empty(),
                "example carries no Allow line: {}",
                example.snippet
            );

            let violation = check_allow(&lines, true);
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
        let rule = AllowHeaderMethodTokensValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "allow_header_method_tokens_valid".into(),
            toml::Value::Table(table),
        );

        rule.validate(&cfg)?;
        Ok(())
    }
}
