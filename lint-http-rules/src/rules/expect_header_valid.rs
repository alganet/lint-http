// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::content_length::content_evidence;
use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::{
    list_members_as_written, quoting_is_balanced, split_semicolons_respecting_quotes,
};
use crate::helpers::quoted_string::{quoted_string_end, validate_quoted_string};
use crate::helpers::shown::describe_octet;
use crate::helpers::token::{find_invalid_token_char, token_run_end};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct ExpectHeaderValid;

/// The one expectation the specification defines, matched without regard to case.
///
/// cite(RFC 9110 § 10.1.1): "The only expectation defined by this specification is "100-continue" (with no defined parameters)."
/// cite(RFC 9110 § 10.1.1): "The Expect field value is case-insensitive."
const HUNDRED_CONTINUE: &str = "100-continue";

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1",
    note: "Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure",
};
const RFC_9110_A: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("A"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
    note: "Collected ABNF for senders: `Expect` with its list construct expanded, which is where the whole value being optional is written out",
};
const RFC_9110_5_6_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
    note: "List sender requirements — the MUST NOT behind the empty-element finding",
};
const RFC_9110_5_6_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
    note:
        "`parameters`, the production this rule's transcribed grammar used to end one term short of",
};
const RFC_9110_15_5_18: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.5.18"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.18",
    note: "417 Expectation Failed — what the status the repeat check reads means",
};
const RFC_9110_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
    note: "Requirements Notation — where the sentence that makes an element the ABNF does not generate a violation lives, rather than §2.4 Error Handling",
};
const RFC_9110_B_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("B.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.3",
    note: "Changes from RFC 7231: the list-based grammar for `Expect` was restored, and an expectation's parameters may be empty — two sentences that decide how this rule reads the field",
};

impl RuleMeta for ExpectHeaderValid {
    fn id(&self) -> &'static str {
        "expect_header_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "error"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Expect Header Valid")
    }

    fn description(&self) -> &'static str {
        "Reads a request's `Expect` field as `#expectation`, where each member is `token [ \"=\" ( token / quoted-string ) parameters ]`, and reports the client requirements RFC 9110 §10.1.1 places on it.\n\n**A 100-continue expectation on a request with no content is a MUST NOT.** §10.1.1 says so in one line, and the expectation asks a server to decide about content the message never carried. Content is the octet stream left once framing is removed, so the captured count answers when there is one and the sender's `Content-Length` answers otherwise; a chunked request whose only chunk is the terminator carries none. Where a capture records neither, this rule reports — unlike the rules that report content being *present*, which stay silent on the same silence. The proxy always records the count, so that gap belongs to captures written elsewhere.\n\n**A repeat of a request the chain answered with 417 is reported.** §10.1.1 asks a client that receives 417 to repeat without the expectation, since the status only means the response chain does not support expectations. The comparison is against the most recent exchange for this resource *using this method* — a request with another method is not the one being repeated.\n\n**A value or parameters on `100-continue` is advice, not a violation.** The grammar admits both on any expectation and the specification says only that it defines none for this one. What it costs is real: a recipient matching the member against `100-continue` sees a different member, which §10.1.1 lets it answer with 417.\n\n**Other expectation names are not reported.** `expectation` is a `token` with no registry behind it, and the only consequence the specification states is a server's MAY to answer 417.\n\n**Syntax is judged as written and as one list.** The field lines are joined before the members are counted, because `#expectation` makes them one list and a member may be written at a line boundary. The value is read octet by octet rather than decoded, since an expectation's value may be a `quoted-string` and `qdtext` admits `obs-text` — refusing the field would hide the legal value and the illegal one alike. `Expect:` with nothing after it is a conforming *empty list* (Appendix A writes the whole value as optional) and is not reported; an empty element inside a list is §5.6.1.1's sender MUST NOT and is. That the field is a list at all is recent: RFC 7231 wrote it as the bare string `100-continue`, and RFC 9110 §B.3 records restoring the list grammar.\n\n**Whitespace is not tolerated where the grammar has none.** `expectation` puts no `OWS` around its `=`, and §5.6.6's note says parameters allow none around theirs either, so `a = b` and `a=b; c = d` are reported. §2.2 is what makes a value the ABNF does not generate a finding rather than a preference.\n\n**Not checked here:** whether a client that waited for a 100 (Continue) sent the expectation, and how long it waited — §10.1.1 states both as client requirements, and neither the waiting nor its duration appears in a captured message. The server requirements in the same section (ignoring the expectation in an HTTP/1.0 request, sending a final status after a 100) are about a response and are outside a rule scoped to the client. `Expect` in a *response* is not reported: §10.1 defines these as request header fields, but no sentence forbids sending one elsewhere."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_10_1_1,
            RFC_9110_A,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_6,
            RFC_9110_15_5_18,
            RFC_9110_2_2,
            RFC_9110_B_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "A 100-continue expectation on a request that has content, an extension expectation whose value carries parameters, and an empty list — all three derive from `#expectation`",
                ),
                snippet: "PUT /upload HTTP/1.1\nHost: example.com\nContent-Type: text/plain\nContent-Length: 8\nExpect: 100-continue\n\nabcdefgh\n\nGET /foo HTTP/1.1\nHost: example.com\nExpect: hyper-fast=yes;level=\"9\", slow\n\nGET /bar HTTP/1.1\nHost: example.com\nExpect:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "A 100-continue expectation with no content to weigh in on, an empty list element, and a member whose name is not a token",
                ),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nExpect: 100-continue\n# No content, so RFC 9110 §10.1.1's client MUST NOT applies\n\nGET /bar HTTP/1.1\nHost: example.com\nExpect: 100-continue, , slow\n# The middle element is empty (RFC 9110 §5.6.1.1)\n\nGET /baz HTTP/1.1\nHost: example.com\nExpect: a/b\n# '/' is not a tchar, so 'a/b' is not a token",
            },
        ]
    }
}

impl Rule for ExpectHeaderValid {
    /// Every requirement this rule enforces opens "A client", and the field is
    /// one of the request context fields. `Client` is what lets the rule run on
    /// a capture with no response — a request-only lint still measures a header
    /// section the client has already written.
    ///
    /// cite(RFC 9110 § 10.1): "The request header fields below provide additional information about the request context, including information about the user, user agent, and resource behind the request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The field is defined on the request, so the request is where it is read.
            //
            // cite(RFC 9110 § 10.1.1): "The "Expect" header field in a request indicates a certain set of behaviors (expectations) that need to be supported by the server in order to properly handle this request."
            //
            // `#expectation` makes however many field lines carry it one list, so
            // they are joined before the members are counted — a member written at a
            // line boundary is one member. The join is over the octets as written
            // because an `expectation`'s value may be a `quoted-string`, and `qdtext`
            // admits `obs-text`: `to_str` refused such a value and skipped the whole
            // field with it, so a legal `Expect: a="caf%xE9"` and an illegal
            // `Expect: %xFF` were equally invisible.
            //
            // That the field is a list at all is a change this revision made and
            // records by name: RFC 7231 wrote `Expect = "100-continue"`, a single
            // value with no list construct, so a rule transcribed from the previous
            // document would report every second member as junk.
            //
            // cite(RFC 9110 § B.3): "List-based grammar for Expect has been restored for compatibility with RFC 2616."
            let value = combined_field_value_as_written(&tx.request.headers, "Expect")?;

            // Read after the field, not before it: both this and a missing `Expect`
            // end the rule, and the header probe is one map lookup where the config
            // read is several.
            let report = |message: String| Some(self.violation(ctx.severity, message));

            // A list of no members, which is not a list with an empty member in it —
            // the two look alike and only one of them is a defect. The sender-expanded
            // grammar wraps the whole value in `[ ]`, and a comma is not `OWS`, so a
            // value that trims to nothing is a value with no commas and no members.
            //
            // cite(RFC 9110 § A): "Expect = [ expectation *( OWS "," OWS expectation ) ]"
            if trim_ows(&value).is_empty() {
                return None;
            }

            let Some(members) = members_of(&value) else {
                return report(format!(
                    "Expect has a quoted-string that is never terminated: '{}'",
                    crate::helpers::shown::shown_in_finding(&value)
                ));
            };

            // cite(RFC 9110 § 10.1.1): "The Expect field value is case-insensitive."
            let mut hundred_continue: Option<Expectation<'_>> = None;
            for (i, member) in members.iter().enumerate() {
                if member.is_empty() {
                    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                    return report(format!(
                        "Expect writes an empty list element (member {} of {}): '{}'",
                        i + 1,
                        members.len(),
                        crate::helpers::shown::shown_in_finding(&value)
                    ));
                }
                let e = match parse_expectation(member) {
                    Ok(e) => e,
                    Err(msg) => return report(msg),
                };
                if hundred_continue.is_none() && e.name.eq_ignore_ascii_case(HUNDRED_CONTINUE) {
                    hundred_continue = Some(e);
                }
            }

            if let Some(e) = hundred_continue {
                // The strongest sentence in the section, and the one no rule in the
                // catalogue answered. "Content" is the octet stream after framing is
                // taken off, which is what `content_evidence` measures; a message
                // that shows none is a message that does not include content.
                //
                // The direction matters here in a way it does not for the rules that
                // report content being *present*: those stay silent when a capture
                // records neither an octet count nor a `Content-Length`, and this one
                // speaks. The proxy always records the count, so that silence belongs
                // to captures written elsewhere, and `description()` says on what
                // evidence the finding rests.
                //
                // cite(RFC 9110 § 10.1.1): "A client MUST NOT generate a 100-continue expectation in a request that does not include content."
                // cite(RFC 9110 § 10.1.1): "A "100-continue" expectation informs recipients that the client is about to send (presumably large) content in this request"
                if content_evidence(&tx.request.headers, tx.request.body_length).is_none() {
                    return report(
                        "Request carries a 100-continue expectation but no content: the expectation \
                         asks the server to weigh in before content the message never had"
                            .to_string(),
                    );
                }

                // A 417 says the response chain does not understand expectations, so
                // repeating the request with the same expectation asks again for
                // something already refused. The history is scoped to this resource by
                // the rule's `ByResource` query; the search is for the most recent
                // exchange using *this method*, because a request with another method
                // is not the one being repeated and its status says nothing about this
                // one.
                //
                // cite(RFC 9110 § 15.5.18): "The 417 (Expectation Failed) status code indicates that the expectation given in the request's Expect header field (Section 10.1.1) could not be met by at least one of the inbound servers."
                // cite(RFC 9110 § 10.1.1): "A client that receives a 417 (Expectation Failed) status code in response to a request containing a 100-continue expectation SHOULD repeat that request without a 100-continue expectation, since the 417 response merely indicates that the response chain does not support expectations (e.g., it passes through an HTTP/1.0 server)."
                if history
                    .iter()
                    .find(|prev| prev.request.method == tx.request.method)
                    .is_some_and(|prev| {
                        prev.response.as_ref().is_some_and(|r| r.status == 417)
                            && carries_hundred_continue(&prev.request.headers)
                    })
                {
                    return report(
                        "Request repeats one the response chain answered with 417 (Expectation Failed) \
                         and still carries a 100-continue expectation"
                            .to_string(),
                    );
                }

                // No MUST is broken by writing one: the grammar admits a value and
                // parameters on any expectation, and the specification declines to
                // define either for this one rather than forbidding them. What it
                // costs is the expectation itself — a server comparing the member
                // against `100-continue` finds something else, which is the member
                // the next sentence hands a 417.
                //
                // cite(RFC 9110 § 10.1.1): "A server that receives an Expect field value containing a member other than 100-continue MAY respond with a 417 (Expectation Failed) status code to indicate that the unexpected expectation cannot be met."
                if e.has_arguments() {
                    return report(format!(
                        "Expect writes the 100-continue expectation with an argument ('{}'); the \
                         specification defines no value or parameters for it, so a recipient matching \
                         the member against 100-continue sees a different expectation and may answer \
                         417 (Expectation Failed). This is advice: the grammar admits the argument",
                        crate::helpers::shown::shown_in_finding(e.member)
                    ));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// One `expectation`, as far as this rule needs to read it.
#[derive(Debug)]
pub(crate) struct Expectation<'a> {
    /// The leading `token`.
    name: &'a str,
    /// The member as written, for a message that has to show it.
    member: &'a str,
}

impl Expectation<'_> {
    /// Whether anything followed the name — a value, parameters, or both.
    ///
    /// The member begins with the name by construction, so their lengths
    /// differing is the whole question; keeping it as a third field would be one
    /// more thing for two construction sites to agree about.
    fn has_arguments(&self) -> bool {
        self.member.len() > self.name.len()
    }
}

/// The members of a combined `Expect` value, each `OWS`-trimmed, or `None` when
/// the quoting never closes.
///
/// Both readers of the field go through here so they cannot disagree about what
/// a member is. After a DQUOTE that never closes, no comma past it is a
/// separator and everything after collapses into one segment, so a member list
/// taken from such a value is invented rather than read — the caller judging the
/// current request reports that, and the caller looking at an earlier request
/// simply has no answer.
fn members_of(value: &str) -> Option<Vec<&str>> {
    quoting_is_balanced(value).then(|| list_members_as_written(value))
}

/// Parse one OWS-trimmed, non-empty list member against `expectation`.
///
/// The member arrives one `char` per octet, so every octet no production admits
/// reaches the check that owns it rather than being folded into "not valid
/// UTF-8" upstream.
///
/// The trailing `parameters` was missing from this rule's transcription of the
/// production, which made `Expect: wait=long;level=9` — a value the grammar
/// generates — a reported defect. Note where the bracket closes: `parameters`
/// is inside the optional group, so an expectation with no value has nowhere to
/// hang them and `wait;level=9` derives from nothing.
///
/// cite(RFC 9110 § 10.1.1): "expectation = token [ "=" ( token / quoted-string ) parameters ]"
/// cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
pub(crate) fn parse_expectation(member: &str) -> Result<Expectation<'_>, String> {
    // The name is the leading run of `tchar`; what stops it is either the `=`
    // the production writes or an octet the member had no business carrying.
    let name_end = token_run_end(member);
    let name = &member[..name_end];
    if name.is_empty() {
        return Err(format!(
            "Expect member '{}' does not begin with a token: found {}",
            crate::helpers::shown::shown_in_finding(member),
            first_octet_of(member)
        ));
    }

    let tail = &member[name_end..];
    let Some(stopper) = tail.chars().next() else {
        return Ok(Expectation { name, member });
    };
    if stopper != '=' {
        return Err(format!(
            "Invalid octet {} after the Expect expectation name '{}': the production admits only \
             '=' there, and `parameters` are inside the group the '=' opens",
            describe_octet(stopper as u8),
            crate::helpers::shown::shown_in_finding(name)
        ));
    }
    let rest = &tail[1..];

    // The production puts no `OWS` between `=` and the value, so the value
    // starts at the very next octet.
    let after_value = if rest.starts_with('"') {
        let Some(end) = quoted_string_end(rest) else {
            return Err(format!(
                "Expect member '{}' has a quoted-string that is never terminated",
                crate::helpers::shown::shown_in_finding(member)
            ));
        };
        validate_quoted_string(&rest[..=end]).map_err(|e| {
            format!(
                "Invalid quoted-string in Expect member '{}': {}",
                crate::helpers::shown::shown_in_finding(member),
                e
            )
        })?;
        &rest[end + 1..]
    } else {
        // A `token` value runs to the first octet no `tchar` admits; whatever
        // follows has to be `parameters`.
        let end = token_run_end(rest);
        if end == 0 {
            return Err(format!(
                "Expect member '{}' has '=' with no token or quoted-string after it: found {}",
                crate::helpers::shown::shown_in_finding(member),
                first_octet_of(rest)
            ));
        }
        &rest[end..]
    };

    validate_parameters(after_value, member)?;

    Ok(Expectation { name, member })
}

/// Name the octet a parse stopped on, or say there was none.
fn first_octet_of(s: &str) -> String {
    s.chars()
        .next()
        .map(|c| describe_octet(c as u8))
        .unwrap_or_else(|| "nothing".into())
}

/// The `parameters` that may follow an expectation's value.
///
/// cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
/// cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
/// cite(RFC 9110 § 5.6.6): "parameter-name  = token"
/// cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
fn validate_parameters(after_value: &str, member: &str) -> Result<(), String> {
    // `*( … )` — an expectation whose value ends the member has none, which is
    // the ordinary case and needs no splitting to establish.
    if after_value.is_empty() {
        return Ok(());
    }

    // The splitter trims `OWS` off each segment, which is exactly the `OWS` the
    // production writes on both sides of the `;` — and only `OWS`, so an
    // `obs-text` octet is not mistaken for whitespace and does not leave an empty
    // segment behind.
    let segments = split_semicolons_respecting_quotes(after_value);

    // Everything before the first `;` belongs to the value, which has already
    // been consumed: what is left of it can only be the `OWS` the production
    // allows before the semicolon. The splitter always yields that leading
    // segment, empty or not.
    if !segments[0].is_empty() {
        return Err(format!(
            "Expect member '{}' has octets after its value that are not parameters: '{}'",
            crate::helpers::shown::shown_in_finding(member),
            crate::helpers::shown::shown_in_finding(segments[0])
        ));
    }

    for seg in &segments[1..] {
        let seg = *seg;
        // `[ parameter ]` — the production makes each one optional, so `a=b;`
        // and `a=b;;c=d` both derive. This revision's "Changes from" appendix
        // names the construct and this field's production in the same sentence,
        // which is as close as a document comes to writing the test case.
        //
        // cite(RFC 9110 § B.3): "Parameters in media type, media range, and expectation can be empty via one or more trailing semicolons."
        if seg.is_empty() {
            continue;
        }
        let Ok(parameter) =
            crate::helpers::parameter::parameter_of(seg).expect("the empty segment returned above")
        else {
            return Err(format!(
                "Expect member '{}' has a parameter with no value: '{}'",
                crate::helpers::shown::shown_in_finding(member),
                crate::helpers::shown::shown_in_finding(seg)
            ));
        };
        let (pname, pvalue) = (parameter.name, parameter.value);

        // No `OWS` is written around a parameter's `=`, and the section says so
        // twice — once by writing the production without any, once in prose.
        // **This is the one caller in the tree that reports it.** Six rules
        // reading a media type trim it and publish that as a known leniency, so
        // the shared walk hands the fact back rather than deciding it, and this
        // is where the sentence below is enforced. What changed is the sentence
        // the finding names, not what it catches: the walk here used not to trim
        // at all, so the space in `a = b` landed inside the name and came back as
        // "an octet no `tchar` admits". Every spelling was caught that way --
        // SP and HTAB are `tchar`s in no position, and the splitter has already
        // taken the `OWS` off both ends of the segment -- but the requirement
        // being reported was § 5.6.2's alphabet when the requirement in force is
        // the Note below, which is about this character and says so.
        //
        // cite(RFC 9110 § 5.6.6): "Note: Parameters do not allow whitespace (not even "bad" whitespace) around the "=" character."
        if parameter.whitespace_beside_equals {
            return Err(format!(
                "Expect member '{}' writes whitespace beside the '=' of parameter '{}'; parameters do not allow whitespace around that character, not even \"bad\" whitespace",
                crate::helpers::shown::shown_in_finding(member),
                crate::helpers::shown::shown_in_finding(seg)
            ));
        }
        if pname.is_empty() {
            return Err(format!(
                "Expect member '{}' has a parameter with no name: '{}'",
                crate::helpers::shown::shown_in_finding(member),
                crate::helpers::shown::shown_in_finding(seg)
            ));
        }
        if let Some(c) = find_invalid_token_char(pname) {
            return Err(format!(
                "Invalid octet {} in Expect parameter name '{}'",
                describe_octet(c as u8),
                crate::helpers::shown::shown_in_finding(pname)
            ));
        }
        // `parameter-value = ( token / quoted-string )`, read by the function
        // that owns the alternation -- a ninth copy of it, found while giving the
        // `parameters` walk a home. No second "does the quoted-string end the
        // value" test is needed: everything such a test would catch,
        // `validate_quoted_string` already rejects, since it requires the first
        // and last octets to be the DQUOTE with no unescaped one between them.
        match crate::helpers::word::token_or_quoted_string(pvalue) {
            Ok(_) => {}
            Err(crate::helpers::word::WordDefect::Empty) => {
                return Err(format!(
                    "Expect member '{}' has a parameter with an empty value: '{}'",
                    crate::helpers::shown::shown_in_finding(member),
                    crate::helpers::shown::shown_in_finding(seg)
                ))
            }
            Err(crate::helpers::word::WordDefect::NotQuotedString(e)) => {
                return Err(format!(
                    "Invalid quoted-string in Expect parameter '{}': {}",
                    crate::helpers::shown::shown_in_finding(seg),
                    e
                ))
            }
            Err(crate::helpers::word::WordDefect::NotToken(c)) => {
                return Err(format!(
                    "Invalid octet {} in Expect parameter value '{}'",
                    describe_octet(c as u8),
                    crate::helpers::shown::shown_in_finding(pvalue)
                ))
            }
        }
    }

    Ok(())
}

/// Whether a header section carries a `100-continue` expectation, for the one
/// caller that reads a *previous* request rather than the one being checked.
///
/// A member that does not parse is not a `100-continue` expectation, so a
/// malformed `Expect` on the earlier request leaves the repeat check silent —
/// that request's own defect is reported where it was made.
fn carries_hundred_continue(headers: &hyper::HeaderMap) -> bool {
    let Some(value) = combined_field_value_as_written(headers, "Expect") else {
        return false;
    };
    members_of(&value).is_some_and(|members| {
        members.into_iter().any(|m| {
            // The name is compared before the member is parsed: a member that is
            // not this expectation costs a `tchar` run rather than a full parse
            // and the error string that parse would have built and thrown away.
            m[..token_run_end(m)].eq_ignore_ascii_case(HUNDRED_CONTINUE)
                && parse_expectation(m).is_ok()
        })
    })
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExpectHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// A request whose `Expect` lines are given as raw octets, carrying content
    /// so the 100-continue MUST NOT is not what fires.
    fn tx_with_expect_lines(lines: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert("host", HeaderValue::from_static("example.com"));
        for l in lines {
            hm.append(
                "expect",
                HeaderValue::from_bytes(l).expect("header value from octets"),
            );
        }
        tx.request.headers = hm;
        tx.request.method = "POST".into();
        tx.request.body_length = Some(8);
        tx
    }

    fn judge_with(
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
    ) -> Option<Violation> {
        let rule = ExpectHeaderValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        judge_with(tx, &crate::transaction_history::TransactionHistory::empty())
    }

    fn judge_value(value: &str) -> Option<Violation> {
        judge(&tx_with_expect_lines(&[value.as_bytes()]))
    }

    #[rstest]
    // Members the grammar generates.
    #[case("100-continue", false)]
    #[case("foo", false)]
    #[case("100-continue, foo", false)]
    #[case("a=b", false)]
    #[case("a=\"quoted\"", false)]
    // `parameters` is the last term of `expectation`, and the rule used to stop
    // one term short of it — but the term is inside the optional group, so a
    // member with no value has nowhere to write one.
    #[case("wait=long;level=9", false)]
    #[case("wait;level=9", true)]
    #[case("a=b;c=d", false)]
    #[case("a=b ; c=\"d\"", false)]
    #[case("a=\"q\";c=d", false)]
    #[case("a=b;", false)]
    #[case("a=b;;c=d", false)]
    // `#expectation` with no members: the sender-expanded grammar wraps the
    // whole value in brackets.
    #[case("", false)]
    #[case("   ", false)]
    // An empty element inside a list is the other thing entirely.
    #[case("a,,b", true)]
    #[case(",", true)]
    // A `quoted-string` may hold a comma, and splitting on every comma cut this
    // member in half.
    #[case("a=\"x,y\"", false)]
    // Token defects.
    #[case("a/b", true)]
    #[case("=value", true)]
    #[case("a=", true)]
    // Whitespace beside the `=`. All three were caught before the shared walk
    // existed, as "an octet no tchar admits"; what the finding now names is the
    // Note that is actually about this character.
    #[case("a= b", true)]
    #[case("a = b", true)]
    #[case("a=b; c = d", true)]
    #[case("a=\t b", true)]
    #[case("a=\"unterminated", true)]
    #[case("a=b junk", true)]
    #[case("a=b;=x", true)]
    #[case("a=b;c", true)]
    #[case("a=b;c=", true)]
    fn expect_syntax_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = judge_value(value);
        assert_eq!(
            v.is_some(),
            expect_violation,
            "case '{}' produced {:?}",
            value,
            v.map(|x| x.message)
        );
    }

    /// The one caller in the tree that reports § 5.6.6's whitespace Note, pinned
    /// whole. A `is_some()` case cannot tell this finding from the `tchar` one it
    /// replaced, and the whole change is which requirement the message names.
    #[test]
    fn whitespace_beside_the_equals_names_the_note_that_forbids_it() {
        // The parameter level, not the expectation's own `=`: `expectation =
        // token [ "=" ( token / quoted-string ) parameters ]`, so `a = b` alone
        // is a name-and-value pair and its whitespace is caught one branch up.
        let v = judge_value("a=b; c = d").expect("§ 5.6.6 forbids whitespace around the '='");
        assert_eq!(
            v.message,
            "Expect member 'a=b; c = d' writes whitespace beside the '=' of parameter 'c = d'; \
             parameters do not allow whitespace around that character, not even \"bad\" whitespace"
        );
    }

    #[test]
    fn scope_is_client() {
        assert_eq!(ExpectHeaderValid.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn empty_value_is_a_conforming_empty_list() {
        // The published NonCompliant example used to open with `Expect:` under
        // the words "Empty element", and a `#[case]` asserted the report.
        // `Expect = [ expectation *( OWS "," OWS expectation ) ]` says otherwise.
        assert!(judge_value("").is_none());
    }

    #[test]
    fn obs_text_inside_a_quoted_string_is_read_not_skipped() {
        // `qdtext` admits `obs-text`, so this member conforms — and `to_str()`
        // used to refuse the line and skip the field with it.
        let tx = tx_with_expect_lines(&[b"a=\"caf\xE9\""]);
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn obs_text_in_a_token_is_reported() {
        // The same read, the other direction: `tchar` admits no octet at or
        // above %x80, and this one used to leave with the decode.
        let tx = tx_with_expect_lines(&[b"caf\xE9"]);
        let msg = judge(&tx).expect("obs-text is not a tchar").message;
        assert!(msg.contains("0xE9"), "{msg}");
    }

    #[test]
    fn a_member_may_be_written_at_a_line_boundary() {
        // Two field lines are one list, so the quoted-string spanning them is
        // one member. Reading the lines separately reported it as unterminated.
        let tx = tx_with_expect_lines(&[b"a=\"x", b"y\""]);
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn unbalanced_quoting_reports_the_value_rather_than_its_members() {
        let msg = judge_value("a=\"x, b").expect("never terminated").message;
        assert!(msg.contains("never terminated"), "{msg}");
    }

    #[test]
    fn hundred_continue_without_content_is_the_must_not() {
        let mut tx = tx_with_expect_lines(&[b"100-continue"]);
        tx.request.body_length = Some(0);
        let msg = judge(&tx).expect("MUST NOT").message;
        assert!(msg.contains("no content"), "{msg}");
    }

    #[test]
    fn hundred_continue_with_content_is_clean() {
        let mut tx = tx_with_expect_lines(&[b"100-continue"]);
        tx.request.body_length = Some(4);
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn hundred_continue_length_declared_but_body_not_captured() {
        // No captured count, so the sender's own declaration is the evidence.
        let mut tx = tx_with_expect_lines(&[b"100-continue"]);
        tx.request.body_length = None;
        tx.request
            .headers
            .insert("content-length", HeaderValue::from_static("120"));
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn chunked_framing_is_not_content() {
        // A chunked request whose only chunk is the terminator carries nothing,
        // and the framing field does not stand in for the octets.
        let mut tx = tx_with_expect_lines(&[b"100-continue"]);
        tx.request.body_length = Some(0);
        tx.request
            .headers
            .insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert!(judge(&tx).is_some());
    }

    #[test]
    fn hundred_continue_matched_without_regard_to_case() {
        let mut tx = tx_with_expect_lines(&[b"100-Continue"]);
        tx.request.body_length = Some(0);
        assert!(judge(&tx).is_some());
    }

    #[test]
    fn an_argument_on_hundred_continue_is_advice_not_a_grammar_defect() {
        let msg = judge_value("100-continue=param").expect("advice").message;
        assert!(msg.contains("417"), "{msg}");
        assert!(msg.contains("advice"), "{msg}");
    }

    #[test]
    fn an_unknown_expectation_is_not_reported() {
        // `expectation` is a token and there is no registry of them; a server's
        // only stated recourse is a MAY to answer 417.
        assert!(judge_value("wild-guess").is_none());
    }

    fn prior(
        method: &str,
        status: u16,
        expect: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        let mut hm = hyper::HeaderMap::new();
        if let Some(e) = expect {
            hm.insert("expect", HeaderValue::from_str(e).expect("expect value"));
        }
        tx.request.headers = hm;
        tx.request.body_length = Some(8);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: Some(0),
            trailers: None,
        });
        tx
    }

    fn judge_with_history(
        entries: Vec<crate::http_transaction::HttpTransaction>,
    ) -> Option<Violation> {
        judge_with(
            &tx_with_expect_lines(&[b"100-continue"]),
            &crate::transaction_history::TransactionHistory::from_transactions(entries),
        )
    }

    #[test]
    fn repeating_after_a_417_still_expecting_is_reported() {
        let msg = judge_with_history(vec![prior("POST", 417, Some("100-continue"))])
            .expect("417 repeat")
            .message;
        assert!(msg.contains("417"), "{msg}");
    }

    #[test]
    fn a_417_to_another_method_is_not_the_request_being_repeated() {
        assert!(judge_with_history(vec![prior("HEAD", 417, Some("100-continue"))]).is_none());
    }

    #[test]
    fn a_417_the_client_already_heeded_is_not_reported_again() {
        // The most recent exchange with this method succeeded without the
        // expectation, so this request is not the repeat the sentence is about.
        // Built oldest-first and handed over newest-first, which is the order
        // `TransactionHistory` is documented to take.
        let refused = prior("POST", 417, Some("100-continue"));
        let accepted = prior("POST", 200, None);
        assert!(judge_with_history(vec![accepted, refused]).is_none());
    }

    #[test]
    fn a_417_to_a_request_that_expected_nothing_is_not_this_finding() {
        assert!(judge_with_history(vec![prior("POST", 417, None)]).is_none());
    }

    #[test]
    fn no_expect_field_is_no_finding() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.body_length = Some(0);
        assert!(judge(&tx).is_none());
    }

    #[rstest]
    #[case("a=\"bad\x01\"")]
    #[case("a=\"bad\x7f\"")]
    fn control_octets_in_a_quoted_string_are_reported(#[case] member: &str) {
        // Judged through the member parser rather than through a transaction:
        // `HeaderValue` refuses these octets outright, so a capture cannot carry
        // one to the rule. The production still forbids them, and the check that
        // owns it is shared with the rules whose values arrive by other routes.
        let msg = parse_expectation(member).expect_err("control octet");
        assert!(msg.contains("Control character"), "{msg}");
    }

    #[test]
    fn htab_is_qdtext() {
        assert!(judge_value("a=\"good\tvalue\"").is_none());
    }

    #[test]
    fn an_escaped_backslash_does_not_swallow_the_closing_quote() {
        assert!(judge_value("a=\"value\\\\\"").is_none());
    }

    #[test]
    fn an_escaped_quote_leaves_the_string_unterminated() {
        let msg = judge_value("a=\"value\\\"").expect("unterminated").message;
        assert!(msg.contains("never terminated"), "{msg}");
    }

    #[test]
    fn a_reported_value_does_not_carry_a_corrupting_octet_into_the_message() {
        // HTAB is `qdtext`, so this value is legal inside its quoted-string and
        // reaches the rule intact — and a raw tab in a finding breaks the line
        // rather than describing it.
        let tx = tx_with_expect_lines(&[b"a=\"x\ty\",,b"]);
        let msg = judge(&tx).expect("empty element").message;
        assert!(!msg.contains('\t'), "{msg}");
        assert!(msg.contains("\\t"), "{msg}");
    }

    #[test]
    fn octets_after_a_quoted_string_are_not_parameters() {
        let msg = judge_value("a=\"good\"extra").expect("trailing").message;
        assert!(msg.contains("not parameters"), "{msg}");
    }
}
