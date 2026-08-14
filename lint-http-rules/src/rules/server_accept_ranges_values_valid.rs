// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// The `Accept-Ranges` response field is a list of range units, and this rule
/// reads it as one.
pub struct ServerAcceptRangesValuesValid;

impl Rule for ServerAcceptRangesValuesValid {
    fn id(&self) -> &'static str {
        "server_accept_ranges_values_valid"
    }

    /// The field is defined on a response and nothing defines it on a request,
    /// which is what the enum records. It also filters: `Server` is the one
    /// variant this engine acts on, and it means "skip a transaction with no
    /// response" -- the same thing `tx.response` says below, by a second
    /// mechanism.
    ///
    // cite(RFC 9110 § 14.3): "The "Accept-Ranges" field in a response indicates whether an upstream server supports range requests for the target resource."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // Both of the sections the field is defined for, and every line inside
        // each of them. This used to be one `get_header_str` on the header
        // section, which reads the *first* line of it: a response advertising
        // `bytes` on one line and `none` on the next was read as advertising
        // `bytes`, and a response advertising anything at all in its trailer
        // section was read as advertising nothing.
        //
        // The lines of one section are joined and the sections are not. Appending
        // a field line to the one before it is defined within a field section --
        // a trailer is a separate section arriving after the content -- so what
        // is measured against the list production is each section's own value.
        //
        // A response carrying no `Accept-Ranges` at all reaches none of this and
        // is not a finding: the loop runs over nothing. The whole feature is
        // optional, and a server is under no obligation to say anything about it.
        //
        // cite(RFC 9110 § 14): "Range requests are an OPTIONAL feature of HTTP, designed so that recipients not implementing this feature (or not supporting it for the target resource) can respond as if it is a normal GET request without impacting interoperability."
        let mut units: Vec<String> = Vec::new();
        for section in crate::helpers::accept_ranges::field_sections(resp) {
            let mut lines: Vec<&str> = Vec::new();
            for hv in section.get_all("accept-ranges").iter() {
                // `to_str` refuses every octet outside visible US-ASCII, and the
                // whole of this field is built from `token`, whose characters
                // are a subset of that -- so the refusal is never a false alarm
                // here and no other rule owns the field's syntax to report it.
                // The line used to be handed to a reader that folds an absent
                // field into an unreadable one, so the rule said nothing at all
                // about a value no production admits.
                //
                // What makes it a finding is not that the value failed to be
                // UTF-8: a `0xC3 0xA9` that decodes to a perfectly good `é` is
                // refused as readily as a lone `0xFF`, and neither octet is one
                // a range unit name is allowed to be built from.
                //
                // cite(RFC 9110 § 5.6.2): "Tokens are short textual identifiers that do not include whitespace or delimiters."
                // cite(RFC 9110 § 5.6.2, label: tchar grammar): "tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA ; any VCHAR, except delimiters"
                let Ok(value) = hv.to_str() else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Accept-Ranges holds an octet no range-unit admits: a range unit name is a token, whose characters are all visible US-ASCII".into(),
                    });
                };
                lines.push(value.trim());
            }
            if lines.is_empty() {
                continue;
            }

            // Comma SP, in the order the lines arrived, because that is the
            // value a recipient acts on. The field's definition allows it: the
            // exception in the sentence below turns on whether the field is a
            // comma-separated list, and `acceptable-ranges = 1#range-unit` is
            // one -- so several lines here are not a duplication to report but a
            // single list to read.
            //
            // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
            // cite(RFC 9110 § 14.3, label: acceptable-ranges grammar): "acceptable-ranges = 1#range-unit"
            let value = lines.join(", ");

            if let Err(e) = read_units(&value, &mut units) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid Accept-Ranges field value '{}': {}", value, e),
                });
            }
        }

        // `none` says the server supports no kind of range request at all, so a
        // field that lists it beside a unit it does support says both. Nothing
        // forbids the combination -- the description used to claim a MUST NOT
        // that no sentence of § 14.3 states -- but a client cannot act on both
        // halves, and one of the two is what it will act on.
        //
        // The old check counted the list's elements instead of looking at them,
        // so `Accept-Ranges: none, none` was reported for combining `none` with
        // other range-units when there was no other range-unit.
        //
        // What the second sentence buys is the condition travelling with the
        // MAY -- "does not support any kind of range request" -- which is the
        // state a server is in when it sends this name, and not the state of one
        // listing a unit beside it. The third says the name means nothing else.
        //
        // The question is asked of the response rather than of a field value,
        // because a header section advertising `bytes` and a trailer section
        // advertising `none` are two well-formed lists and one contradiction.
        //
        // cite(RFC 9110 § 14.3): "A server that does not support any kind of range request for the target resource MAY send"
        // cite(RFC 9110 § 14.3): "to advise the client not to attempt a range request on the same request path.  The range unit "none" is reserved for this purpose."
        let mut others: Vec<&str> = Vec::new();
        for unit in units.iter().map(String::as_str) {
            // A unit named twice is named once in the message: the finding is
            // about which units sit beside `none`, and repeating one of them
            // says nothing further about that.
            if unit != "none" && !others.contains(&unit) {
                others.push(unit);
            }
        }
        if units.iter().any(|u| u == "none") && !others.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Accept-Ranges advertises '{}' beside 'none', which is reserved for advising that no kind of range request is supported: the field says both that this resource supports range requests and that it does not (advice: nothing forbids it)",
                    others.join("', '")
                ),
            });
        }

        // Three things a well-formed `Accept-Ranges` can still be, none of them
        // reported here, all of them named so the silence is not read as an
        // oversight.
        //
        // *A unit nobody registered* is not a finding. The modal is "ought to
        // be", which is weaker than SHOULD, and this rule holds no copy of the
        // registry to check a name against in any case -- the registry is where
        // the check would have to live, and adding a name to it is IETF Review.
        //
        // *In a trailer section rather than a header section* is a preference
        // stated with its own reason and no modal at all. A response advertising
        // after its content is doing what the field permits.
        //
        // *A promise the next request will be honoured* is the one thing this
        // field explicitly does not make, and the sentence saying so is addressed
        // to the client. Nothing in it measures the response that carried it.
        //
        // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
        // cite(RFC 9110 § 16.5.1): "The "HTTP Range Unit Registry" defines the namespace for the range unit names and refers to their corresponding specifications."
        // cite(RFC 9110 § 14.3): "The Accept-Ranges field MAY be sent in a trailer section, but is preferred to be sent as a header field because the information is particularly useful for restarting large information transfers that have failed in mid-content (before the trailer section is received)."
        // cite(RFC 9110 § 14.3): "Conversely, a client MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses."
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Accept-Ranges Values Valid")
    }

    fn description(&self) -> &'static str {
        "Checks that an `Accept-Ranges` response header field is what RFC 9110 §14.3 defines it to be: a non-empty comma-separated list of range units, each of them a `token`.\n\n**Any range unit name is accepted.** `range-unit = token`, names are case-insensitive, and §14.1 says they \"are intended to be extensible\". The \"HTTP Range Unit Registry\" holds two entries today — `bytes` and `none` — and adding a third takes IETF Review, not a change here, so `Accept-Ranges: pages` is not reported. This rule used to accept `bytes` and `none` only, \"for practical compatibility\", and called every other name an unexpected range-unit.\n\n**An unregistered name is not reported either.** §14.1 says names \"ought to be registered\", which is weaker than SHOULD, and nothing follows from a client meeting a unit it does not know: §14.3 makes the whole field advice a client MAY ignore.\n\n**Both of the field's sections are read, and the lines of each are joined.** §14.3 says `Accept-Ranges` MAY be sent in a trailer section, so a response that advertises only there is advertising. Within one section, `acceptable-ranges = 1#range-unit` makes several field lines one list, appended in order and separated by comma SP — a response saying `bytes` on one line and `none` on the next is saying both. The sections are not joined to each other: appending a field line to the one before it is defined within a field section, and a trailer arrives after the content as a section of its own.\n\n**The list is measured as a sender's, not as a recipient's.** §5.6.1.2 tells recipients to parse and ignore empty list elements, which is what the shared list reader does and why it cannot answer this rule's question: §5.6.1.1 says \"a sender MUST NOT generate empty list elements\", so `Accept-Ranges: bytes,,none` is reported for the hole rather than counted as two units. A value with no non-empty element at all — `Accept-Ranges: ,` or an empty field line — is not `1#range-unit` either. An octet outside visible US-ASCII is reported for what it is: every character of a `token` is visible US-ASCII, so being valid UTF-8 does not make one admissible.\n\n**`none` beside another unit is reported as advice, not as a violation.** §14.3 grants a MAY to a server that \"does not support any kind of range request for the target resource\" to send `Accept-Ranges: none`, and reserves the name for that purpose. A field that lists `none` next to a unit it does support says both things at once; no sentence forbids it, and a client will act on one of the two halves.\n\n**What else it does not report.** A trailer section carrying the field rather than a header section — §14.3 prefers the header section, gives its reason, and attaches no modal. And a response whose next range request is answered in full: §14.3 says in as many words that a client \"MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses\", which is addressed to the client and measures nothing about the response that carried the field."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3",
                note: "`Accept-Ranges`: `acceptable-ranges = 1#range-unit`, sent in a response to indicate whether an upstream server supports range requests for the target resource. It grants a MAY to a server that \"does not support any kind of range request for the target resource\" to send `none`, and reserves that name for the purpose — the condition on the MAY is what makes `none` beside another unit worth reporting, and the absence of any prohibition is why the report is advice. The field MAY also be sent in a trailer section, which is where the second field section this rule reads comes from, and the preference for the header section carries no modal. The section's remaining sentences are addressed to clients: the field is advice a client MAY ignore, and a client MUST NOT read it as a promise about the next request",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1",
                note: "Range Units: `range-unit = token`, names case-insensitive, \"intended to be extensible\" — which is why no name is reported for being one this rule has not heard of. Registration is what names \"ought to be\" have, weaker than SHOULD, and this rule holds no registry to measure it with anyway",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.5.1",
                note: "The \"HTTP Range Unit Registry\", which holds `bytes` and `none` today and takes IETF Review to add to. Those two entries are the two this rule used to accept as though they were the grammar",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "Sender Requirements for the list construct: OWS on either side of each comma, and a sender MUST NOT generate empty list elements. §5.6.1.2 tells recipients the opposite — parse and ignore them — so the shared list reader, which drops them, cannot answer this rule's question, and a value with no non-empty element at all is among that section's own examples of an invalid `1#`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "Tokens: `tchar` is \"any VCHAR, except delimiters\", so every character of a range unit name is visible US-ASCII. An octet outside that is reported for being outside the production and not for failing to decode as UTF-8, which refuses a perfectly good `é` for a reason that was never the point",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "Field Order: multiple field lines of one name within a field section are combined in order, separated by comma SP, when the field's definition allows a comma-separated list — which `1#range-unit` is. So several `Accept-Ranges` lines are one list to read rather than a duplication to report, and the joining stops at the section boundary the sentence names",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: bytes\n\nHTTP/1.1 200 OK\nAccept-Ranges: none\n\nHTTP/1.1 200 OK\nAccept-Ranges: BYTES",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a range unit this rule does not have to know)"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: pages",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`none` says no range request is supported, beside a unit that is)"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: none, bytes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a range unit is a token, and a space is not a token character)"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: b ytes",
            },
        ]
    }
}

/// Read one field section's value as a list of range units, appending what it
/// advertised to `units`.
///
/// A range unit is a `token` and nothing narrower. The rule used to accept
/// `bytes` and `none` and report every other name -- its own description said
/// why, "for practical compatibility" -- so a server that partitions a resource
/// into pages and says so was reported for an "unexpected range-unit". Range
/// unit names are an open registry the specification says is meant to grow, and
/// a name this code has never heard of is a name it has to carry rather than
/// reject.
///
/// The list is split here rather than by `list_members`, which drops empty
/// elements: that is the reading a recipient of this field is required to take
/// and the wrong one for the rule measuring what the sender generated. By the
/// time that function answers, the element a sender must not have written is
/// gone -- `bytes,,none` counted two units and said nothing about the hole
/// between them.
///
/// `helpers::headers::list_members_as_written` keeps the empty elements and
/// would answer that half -- and is still not used here, because its other half
/// is wrong for this production. That walk is quote-aware, which is correct
/// exactly where the element admits a `quoted-string` somewhere inside it.
/// `range-unit = token` admits no DQUOTE at all, so here a DQUOTE is a character
/// the member may not hold rather than one opening a quoted-string, and reading
/// it as the latter would make the comma after it data: `by"tes,none` is two
/// members to this production and would arrive as one. The split stays naive for
/// the same reason the trim may stay `str::trim` -- both are decisions about
/// this field's alphabet, and `to_str` above has already refused every octet
/// outside visible US-ASCII, so SP and HTAB are the only whitespace left.
///
// cite(RFC 9110 § 14.1): "Range units are intended to be extensible, as described in Section 16.5."
// cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
fn read_units(value: &str, units: &mut Vec<String>) -> Result<(), String> {
    // The `1` in `1#`. A field line with nothing in it is not a list of one
    // range unit; it is a list of none, which this production does not generate.
    // The specification prints the empty value among its own examples of what a
    // `1#` production makes invalid.
    //
    // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production"
    if value.is_empty() {
        return Err("the value is empty, and a list of range units needs at least one".into());
    }

    for element in value.split(',') {
        // The list construct puts OWS on either side of each comma, and OWS is
        // SP / HTAB. `trim` reaches further than that in general and no further
        // than that here: every octet outside visible US-ASCII was refused
        // before this function was reached, and SP and HTAB are the only
        // whitespace left inside it.
        //
        // cite(RFC 9110 § 5.6.1.1, label: 1#element expansion): "1#element => element *( OWS "," OWS element )"
        // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
        let element = element.trim();

        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if element.is_empty() {
            return Err("a list element is empty, which no sender may generate".into());
        }

        // § 14.1 prints this production alone between two paragraphs, where it
        // is three words short of being quotable; the collected grammar's copy
        // is the same production and is what the other rules reading a range
        // unit quote.
        //
        // cite(RFC 9110 § A): "range-unit = token ranges-specifier = range-unit "=" range-set"
        if let Some(c) = crate::helpers::token::find_invalid_token_char(element) {
            return Err(format!(
                "'{}' is not a range-unit: a range unit name is a token, and {:?} is not a token character",
                element, c
            ));
        }

        // The fold is the specification's and not a tolerance this code chose,
        // which is what lets the `none` comparison below be against a lowercase
        // literal.
        //
        // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
        units.push(element.to_ascii_lowercase());
    }

    Ok(())
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerAcceptRangesValuesValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = ServerAcceptRangesValuesValid;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// A response carrying the given `Accept-Ranges` lines, in the field section
    /// each pair names. Every fixture here is built through this one function,
    /// so a test about a trailer and a test about a header differ in their
    /// argument rather than in how they were assembled.
    fn advertising(lines: &[(Section, &[u8])]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let resp = tx.response.as_mut().expect("the fixture has a response");
        for (section, value) in lines {
            let value = HeaderValue::from_bytes(value).expect("a field value");
            match section {
                Section::Header => resp.headers.append("accept-ranges", value),
                Section::Trailer => resp
                    .trailers
                    .get_or_insert_with(hyper::HeaderMap::new)
                    .append("accept-ranges", value),
            };
        }
        tx
    }

    #[derive(Clone, Copy)]
    enum Section {
        Header,
        Trailer,
    }

    #[rstest]
    #[case(None, false)]
    // The two field values § 14.3 prints, which are the whole of what the
    // section shows a conforming `Accept-Ranges` looking like.
    #[case(Some("bytes"), false)]
    #[case(Some("none"), false)]
    #[case(Some("bytes, bytes"), false)]
    #[case(Some("BYTES"), false)]
    // The two the registry holds are not the two the grammar admits: a range
    // unit is a token, the registry is open, and § 14.1 says names are only
    // "intended to be extensible" -- so a name this rule has never heard of is
    // a name it carries. `pages` is the specification's own example of one
    // (§ 16.5.2), and it used to be reported.
    #[case(Some("pages"), false)]
    #[case(Some("pages, bytes"), false)]
    // `none` is reserved for a server supporting no kind of range request, so
    // listing it beside one it does support says both things at once.
    #[case(Some("none, bytes"), true)]
    #[case(Some("bytes, none"), true)]
    #[case(Some("NONE, Pages"), true)]
    // A unit named twice beside `none` is named once in the finding.
    #[case(Some("bytes, none, bytes"), true)]
    // Two `none`s are a repetition, not a combination. The old check counted
    // the list's elements rather than looking at them, and reported this for
    // combining `none` with other range-units that were not there.
    #[case(Some("none, none"), false)]
    #[case(Some("b ytes"), true)]
    #[case(Some("by\"tes"), true)]
    // The shared list reader drops empty elements, which is what a recipient of
    // this field must do and the opposite of what the rule measuring the sender
    // needs: these three used to be a list of two units, a list of one, and a
    // list of none, all of them silent.
    #[case(Some("bytes,,none"), true)]
    #[case(Some("bytes,"), true)]
    #[case(Some(","), true)]
    #[case(Some(""), true)]
    // OWS on either side of the comma is part of the list construct.
    #[case(Some("bytes ,\tpages"), false)]
    fn accept_ranges_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let lines: Vec<(Section, &[u8])> = header
            .into_iter()
            .map(|h| (Section::Header, h.as_bytes()))
            .collect();
        let tx = advertising(&lines);

        let v = judge(&tx);
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    /// Two lines with one name are one field value, and the rule read the first
    /// of them: `bytes` beside `none` on the next line was read as `bytes` and
    /// said nothing.
    #[rstest]
    #[case(&[b"bytes".as_slice(), b"none"], true)]
    #[case(&[b"none".as_slice(), b"bytes"], true)]
    #[case(&[b"bytes".as_slice(), b"pages"], false)]
    #[case(&[b"bytes".as_slice(), b"b ytes"], true)]
    fn the_lines_of_one_section_are_joined(
        #[case] lines: &[&[u8]],
        #[case] expect_violation: bool,
    ) {
        let lines: Vec<(Section, &[u8])> = lines.iter().map(|l| (Section::Header, *l)).collect();
        assert_eq!(judge(&advertising(&lines)).is_some(), expect_violation);
    }

    /// § 14.3 defines the field for the trailer section too, and the rule opened
    /// the header section alone -- so a response that advertised only there was
    /// read as advertising nothing, whatever it said.
    #[rstest]
    #[case(&[(Section::Trailer, b"b ytes".as_slice())], true)]
    #[case(&[(Section::Trailer, b"bytes".as_slice())], false)]
    // One section says range requests are supported and the other says none is.
    // Each value is a well-formed list on its own; the response is what says
    // both.
    #[case(&[(Section::Header, b"bytes".as_slice()), (Section::Trailer, b"none")], true)]
    fn a_trailer_section_advertises_too(
        #[case] lines: &[(Section, &[u8])],
        #[case] expect_violation: bool,
    ) {
        assert_eq!(judge(&advertising(lines)).is_some(), expect_violation);
    }

    /// The finding names the units sitting beside `none`, and names each of them
    /// once: repeating one says nothing further about the contradiction.
    #[test]
    fn the_units_beside_none_are_named_once_each() {
        let found = judge(&advertising(&[(
            Section::Header,
            b"bytes, none, BYTES, pages".as_slice(),
        )]));
        let message = found.expect("expected a violation").message;
        assert!(
            message.starts_with("Accept-Ranges advertises 'bytes', 'pages' beside 'none'"),
            "unexpected message: {message}"
        );
    }

    /// `0xFF` is not UTF-8 and `0xC3 0xA9` is -- the `é` a server might put in a
    /// field value by accident. Both are outside `token`, which is the whole of
    /// what this field is built from, and the rule used to say nothing about
    /// either: the reader it called folds an unreadable value into an absent one.
    #[rstest]
    #[case(&[0xff][..])]
    #[case("bytes, pag\u{e9}s".as_bytes())]
    fn an_octet_outside_the_grammar_is_reported(#[case] bad: &[u8]) {
        let found = judge(&advertising(&[(Section::Header, bad)]));
        let message = found.expect("expected a violation").message;
        assert!(
            message.contains("no range-unit admits"),
            "reported for another reason: {message}"
        );
    }

    /// Nothing else runs a rule's published examples through it. These used to be
    /// three bare field lines in one snippet, which is neither a message nor one
    /// example -- and under the reading that joins a section's lines, that
    /// snippet is a single value combining `bytes`, `none` and `BYTES`, which
    /// this rule reports. Every block here is one response, and the verdict on it
    /// has to be the one its label promises.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        let mut saw_a_finding = false;
        for ex in ServerAcceptRangesValuesValid.examples() {
            for block in ex.snippet.split("\n\n") {
                let mut lines = block.lines();
                let status_line = lines.next().expect("a response has a status line");
                assert!(
                    status_line.starts_with("HTTP/1.1 "),
                    "not a status line: {status_line:?}"
                );

                let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
                let resp = tx.response.as_mut().expect("the fixture has a response");
                for line in lines {
                    let (name, value) = line
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                    resp.headers.append(
                        hyper::header::HeaderName::from_bytes(name.as_bytes())
                            .unwrap_or_else(|_| panic!("not a field name: {name:?}")),
                        value
                            .parse::<HeaderValue>()
                            .unwrap_or_else(|_| panic!("not a field value: {value:?}")),
                    );
                }

                let found = judge(&tx);
                match ex.compliance {
                    Compliance::Compliant => assert!(
                        found.is_none(),
                        "rule reports its Compliant example {block:?}: {found:?}"
                    ),
                    Compliance::NonCompliant => {
                        assert!(
                            found.is_some(),
                            "rule accepts its NonCompliant example {block:?}"
                        );
                        saw_a_finding = true;
                    }
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerAcceptRangesValuesValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn missing_response_returns_none() {
        let tx = crate::test_helpers::make_test_transaction();
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_accept_ranges_values_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
