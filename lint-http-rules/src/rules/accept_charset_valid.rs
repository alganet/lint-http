// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::accept_charset::{ACCEPT_CHARSET_OBSOLETE, RFC_9110_12_5_2};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::qvalue::{
    QVALUE_MALFORMED, RFC_9110_12_4_2, WEIGHT_DUPLICATED, WEIGHT_EQUALS_WHITESPACE_FORBIDDEN,
    WEIGHT_MALFORMED, WEIGHT_MISSING,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct AcceptCharsetValid;

/// Nine borrowed entries and one of this field's own, and the split says what
/// is particular about `Accept-Charset`.
///
/// `#( ( token / "*" ) [ weight ] )` is `#( codings [ weight ] )` with a
/// different name for the primary, so every entry about the member's *shape* is
/// the one `accept_encoding_parameter_valid` draws and for the same reasons: a
/// separator introducing a weight that is not there, two of something there may
/// be at most one of, a `name=value` pair no derivation of the field produces,
/// a member that is all weight and no charset, and the comma § 5.6.1.1 forbids
/// generating. The primary is a `token` with `*` as its other alternative, so a
/// `@` in a charset name draws the id it draws in a `Content-Type` parameter or
/// a coding name.
///
/// **The tenth is the only thing this field does not share with its three
/// siblings**: § 12.5.2 deprecates the field in the section that defines it, so
/// there is an entry here about the field's presence rather than its value.
/// `Accept`, `Accept-Encoding` and `Accept-Language` have no such entry because
/// their sections retire nothing.
///
/// **Whether a charset name is one anybody registered is not declared here**,
/// and the omission is deliberate. `charset_registered` is named after that
/// question rather than after a field, holds the configured list that stands in
/// for the registry, and reads this field as its second site — so
/// `CHARSET_UNREGISTERED` has one declarer, and an operator narrowing the
/// question narrows it in one place.
static DECLARED: &[&ViolationDef] = &[
    &ACCEPT_CHARSET_OBSOLETE,
    &LIST_MEMBER_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_EMPTY,
    &QVALUE_MALFORMED,
    &WEIGHT_MISSING,
    &WEIGHT_MALFORMED,
    &WEIGHT_DUPLICATED,
    &WEIGHT_EQUALS_WHITESPACE_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_5_6_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
    note: "Recipient Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore. The sender's MUST NOT against generating one is §5.6.1.1's, and this rule reports that one",
};
const RFC_9110_8_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2",
    note: "Charset: where §12.5.2 sends a reader for the names themselves, and the sentence that matches them case-insensitively. Whether a name is one anybody registered is `charset_registered`'s question, not this rule's",
};

impl RuleMeta for AcceptCharsetValid {
    fn id(&self) -> &'static str {
        "accept_charset_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Request Accept-Charset Validity")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept-Charset` header reads as `#( ( token / \"*\" ) [ weight ] )`: each member a charset name or the literal `*`, optionally followed by a weight whose value is a `qvalue` — `0` to `1` with at most three digits after the point. A request carrying the field at all is also reported, because §12.5.2 deprecates it.\n\n**This is RFC 9110 §12.5's fourth content-negotiation field, and it was the one nothing read.** `Accept`, `Accept-Encoding` and `Accept-Language` each had a rule; every defect below drew nothing on this field while the identical shape drew a finding on a sibling. Two instruments could not have said so: a coverage measure counts entries, and a field with no reader has no entry to be uncovered, while a census of field names asks only of names that appeared on some wire.\n\n**There is no parameter list in this field.** A charset may carry a weight and nothing else, so `utf-8;charset=utf-8` is reported however well formed the pair looks in isolation — the same reading `Accept-Language` and `Accept-Encoding` are given, because all three productions put `[ weight ]` after the primary and stop.\n\n**Three consequences of that reading.** `weight` brackets nothing, so `utf-8;` is a separator introducing a weight that is not there. `[ weight ]` is singular, so `utf-8;q=0.5;q=0.8` is two of something there may be at most one of. And a weight is a MAY — `utf-8, iso-8859-1` is as conforming as `utf-8;q=1, iso-8859-1;q=0.8`.\n\n**The `*` is exempt from the name check and nothing else is.** §12.5.2 gives the asterisk a meaning of its own — it matches every charset not mentioned elsewhere in the field — so it is one of the production's two alternatives rather than a charset called `*`. Every other member is a `token`, and a member that begins at the `;` derives from neither alternative for the arithmetic reason `token_empty` names: both have a one-character floor.\n\n**Whether the name is one anybody registered is a different rule's question.** §12.5.2 sends a reader to §8.3.2 for charset names, and `charset_registered` is the rule that holds that question and the configured list standing in for the IANA registry. It reads this field as its second site, so `Accept-Charset: utf8` is its finding rather than one of these. An operator whose clients send long preference lists will want to widen that rule's `allowed` array: the shipped one is three names, chosen when the only site was a `Content-Type` declaring *the* charset of one representation.\n\n**An empty list element is reported and an empty field value is not.** §5.6.1.1 forbids a sender to generate the element and §5.6.1.2 tells a recipient to ignore it, so `utf-8,,iso-8859-1` is a comma the sender may not write — one finding for the line however many gaps it holds, since what is forbidden is generating the element and a line written with three of them is one list with gaps in it. An empty *value* is a different thing: `#` generates the zero-element list, and §12.5.2 neither gives that a meaning nor forbids it, so the line is passed over.\n\n**The deprecation is reported on the request, once per message.** §12.5.2 names a field a *user agent* sends and its Note deprecates the whole field, naming the costs — wasted bandwidth, added latency, and passive fingerprinting. The IANA HTTP Field Name Registry records the status with no direction attached and this section as the field's only reference, so a request carrying one is the deprecated thing being done. Repeated field lines are one value (§5.2), so two lines are one finding.\n\n**A response's Accept-Charset is read for syntax, and nothing is claimed about the direction.** §12.5.2 gives the field no meaning in a response and forbids one nowhere, exactly as §12.5.4 does for `Accept-Language`; the value is still checked, because a malformed one is malformed wherever it appears. The deprecation finding is not raised there, since the sentence retiring the field is about the field a user agent sends.\n\n**The value is read as the octets the sender wrote**, one `char` per octet. Nothing in this grammar is a quoted-string — a member is a `token`, one literal, and the weight's fixed text — so no octet outside visible US-ASCII is legal anywhere in the field, and every one of them lands inside a production that already has an id for it. Refusing to decode the line would name the octet and take every other defect written beside it out of reach."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_12_5_2,
            RFC_9110_12_4_2,
            RFC_9110_5_6_2,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_9110_8_3_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// Both halves are read and they are not one party's. The field is a
    /// request field, so its syntax findings on a request are the client's and
    /// the deprecation is the client's alone — but a response carrying one was
    /// written by a server, and attributing a server's malformed value to the
    /// client would name the wrong peer to fix it.
    ///
    /// cite(RFC 9110 § 12.5.2): "The "Accept-Charset" header field can be sent by a user agent to indicate its preferences for charsets in textual response content."
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(\u{a7}12.5.2's own example: well formed, and the field is deprecated)"),
                snippet:
                    "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: iso-8859-5, unicode-1-1;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the wildcard, and a weight is optional)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8, *;q=0.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a charset may carry a weight and nothing else)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8;charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no qvalue after the separator)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8;",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight there may be at most one of)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8;q=0.5;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a qvalue is 0 or 1, with at most three digits after the point)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8;q=1.5",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the weight writes \"q=\" as one literal, which admits no whitespace)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8;q = 0.5",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a comma with nothing beside it)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf-8,,iso-8859-1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(all weight and no charset)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: ;q=0.5",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a charset name is a token)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Charset: utf@8",
            },
        ]
    }
}

impl Rule for AcceptCharsetValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let mut out = Vec::new();

        // The production this rule is a reading of. A member is a charset name
        // or the asterisk, and at most one weight; nothing else derives from it.
        // cite(RFC 9110 § 12.5.2): "Accept-Charset = #( ( token / "*" ) [ weight ] )"
        // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
        let validate = |headers: &hyper::HeaderMap, party: crate::lint::Party| -> Vec<Violation> {
            // One finding per member. The field states one preference per
            // position, so a value stating two preferences malformedly is two
            // preferences the operator has to correct -- a walk that returned
            // at the first told them about one.
            let mut found = Vec::new();
            for line in crate::helpers::headers::field_lines_as_written(headers, "accept-charset") {
                let val = line.as_str();
                // An empty field value is not an empty element. `#` generates
                // the zero-element list, and unlike §12.5.3 -- which gives an
                // empty `Accept-Encoding` a meaning of its own -- §12.5.2 says
                // nothing about one and forbids nothing, so the line is passed
                // over rather than read as one member the sender left blank.
                // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
                // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                if crate::helpers::headers::trim_ows(val).is_empty() {
                    continue;
                }
                // The walk keeps the empty member, which is the whole
                // difference between the two sentences the `#` construct
                // carries: §5.6.1.2's expansion brackets every position and
                // tells a *recipient* to ignore what that admits, and §5.6.1.1
                // expands the same construct for the sender with nothing
                // bracketed and forbids generating the element. A recipient's
                // walk here would drop the comma before any check could see it.
                //
                // One finding for the line however many gaps it holds: what
                // §5.6.1.1 forbids generating is an empty *element*, and a line
                // written with three of them is one list with gaps in it. The
                // message names the line and not the member, which is the same
                // reading said out loud.
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                let mut saw_an_empty_member = false;
                for part in crate::helpers::list::sender_list_members(val) {
                    if part.is_empty() {
                        saw_an_empty_member = true;
                        continue;
                    }
                    // A comma split with no regard for quoting, and a semicolon
                    // split that does respect it, for one reason each: nothing
                    // in this field's grammar is a quoted-string, so there is
                    // no quoted comma to protect -- and a member that writes
                    // one anyway is measured rather than allowed to swallow the
                    // members after it.
                    let mut iter =
                        crate::helpers::list::split_semicolons_respecting_quotes(part).into_iter();
                    let Some(primary) = iter.next() else {
                        continue;
                    };
                    // `( token / "*" )`. The asterisk is exempted because it is
                    // the production's other alternative rather than a charset
                    // named `*`; §12.5.2 gives it a meaning of its own.
                    // cite(RFC 9110 § 12.5.2): "The special value "*", if present in the Accept-Charset header field, matches every charset that is not mentioned elsewhere in the field."
                    if primary != "*" {
                        // The `1*tchar` floor both alternatives share: a charset
                        // name is a `token` and `*` is a single `tchar`. So a
                        // member that begins at the `;` derives from neither,
                        // for an arithmetic reason a scan for an invalid
                        // character cannot state -- an empty string holds no
                        // offending character, so the scan alone would pass it.
                        if primary.is_empty() {
                            found.push(ctx.by(party).report_with(
                                &TOKEN_EMPTY,
                                format!("Empty charset name in Accept-Charset member '{part}'"),
                            ));
                            continue;
                        }
                        // §12.5.2 sends a reader to §8.3.2 for the names
                        // themselves, and what this rule measures there is the
                        // production the field prints: a `token`. Whether the
                        // name is one anybody registered is `charset_registered`'s
                        // question over the same members.
                        // cite(RFC 9110 § 12.5.2): "Charset names are defined in Section 8.3.2."
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(primary) {
                            found.push(ctx.by(party).report_with(
                                token_character(c),
                                format!(
                                    "Invalid token character '{}' in Accept-Charset member '{}'",
                                    c.escape_debug(),
                                    part
                                ),
                            ));
                            continue;
                        }
                    }

                    // Everything after the charset must be a weight. There is no
                    // parameter list here to be well formed -- the whole member
                    // is `( token / "*" ) [ weight ]`, and `weight` is the fixed
                    // shape `OWS ";" OWS "q=" qvalue`.
                    //
                    // The weight is a MAY, so its absence is never a finding;
                    // what is a finding is anything else in its place, or two of
                    // it. One finding per member rather than per parameter:
                    // `[ weight ]` brackets a single construct, so everything a
                    // member writes after its charset is one thing that is not a
                    // weight, and the loop ends the member rather than the value.
                    // cite(RFC 9110 § 12.5.2): "A user agent MAY associate a quality value with each charset to indicate the user's relative preference for that charset, as defined in Section 12.4.2."
                    let mut weight_seen = false;
                    for param in iter {
                        // Not skipped as an empty parameter slot, because there
                        // are no parameter slots. `weight` brackets nothing, so
                        // a `;` with nothing after it is a weight that is absent
                        // rather than a repetition that ran zero times.
                        if param.is_empty() {
                            found.push(ctx.by(party).report_with(
                                &WEIGHT_MISSING,
                                format!(
                                    "Accept-Charset member '{part}' has a ';' with no weight after it"
                                ),
                            ));
                            break;
                        }
                        let mut nv = param.splitn(2, '=');
                        let raw_name = nv.next().unwrap();
                        let raw_value = nv.next();
                        let name = crate::helpers::headers::trim_ows(raw_name);
                        let val_opt = raw_value.map(crate::helpers::headers::trim_ows);
                        // Trimming is what a recipient does to find the weight;
                        // whether a sender may write the whitespace is a
                        // separate question, and the production answers it. Both
                        // `OWS` it prints stand before `"q="`, which is one
                        // string literal with nothing optional inside it.
                        let whitespace_beside_equals = name.len() != raw_name.len()
                            || raw_value
                                .is_some_and(|v| val_opt.is_some_and(|t| t.len() != v.len()));

                        // Matched without regard to case because §12.4.2 defines
                        // the parameter that way, and this is the only name the
                        // field admits.
                        // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
                        if !name.eq_ignore_ascii_case("q") {
                            found.push(ctx.by(party).report_with(&WEIGHT_MALFORMED, format!(
                                "'{param}' is not a weight, and a weight is the only thing an Accept-Charset member may carry (member '{part}')"
                            )));
                            break;
                        }
                        // §12.5.2 brackets one `[ weight ]` after the primary,
                        // and the message names it because the entry cannot: the
                        // same bracket is written once per field, and a shared
                        // entry may only cite a sentence every rule declaring it
                        // states.
                        if weight_seen {
                            found.push(ctx.by(party).report_with(
                                &WEIGHT_DUPLICATED,
                                format!(
                                    "More than one weight in Accept-Charset member '{part}': §12.5.2 brackets one"
                                ),
                            ));
                            break;
                        }
                        weight_seen = true;

                        // Not `parameter_equals_whitespace_forbidden`: that entry
                        // answers §5.6.6's Note about a `parameter`, and this
                        // field has no parameter list for the Note to be about.
                        if whitespace_beside_equals {
                            found.push(ctx.by(party).report_with(&WEIGHT_EQUALS_WHITESPACE_FORBIDDEN, format!(
                                "Accept-Charset member '{part}' writes whitespace around the weight's '='; the weight is OWS \";\" OWS \"q=\" qvalue, which admits none there"
                            )));
                            break;
                        }

                        // The name matched and the `=` did not, which is one
                        // literal short of a weight rather than a parameter
                        // missing its value: `"q="` is written as a single
                        // string, so there is no `=` here to be absent from a
                        // pair this field never had.
                        let Some(qv) = val_opt else {
                            found.push(ctx.by(party).report_with(&WEIGHT_MALFORMED, format!(
                                "'{name}' is not a weight in Accept-Charset member '{part}': the production writes \"q=\" as one literal and this member stops at the name"
                            )));
                            break;
                        };

                        // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
                        if !crate::helpers::qvalue::valid_qvalue(qv) {
                            found.push(ctx.by(party).report_with(
                                &QVALUE_MALFORMED,
                                format!("Invalid qvalue '{qv}' in Accept-Charset member '{part}'"),
                            ));
                            break;
                        }
                    }
                }
                if saw_an_empty_member {
                    found.push(ctx.by(party).report_with(
                        &LIST_MEMBER_EMPTY,
                        format!(
                            "Accept-Charset holds an empty list element; the field line reads '{val}'. Every position in `#( ( token / \"*\" ) [ weight ] )` holds a charset name, and a comma with nothing beside it holds none"
                        ),
                    ));
                }
            }
            found
        };

        out.extend(validate(&tx.request.headers, crate::lint::Party::Client));

        // The field's presence, on the direction §12.5.2 is written about. One
        // finding per message and not per line: repeated field lines are one
        // value, so a request writing two is one deprecated field.
        // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
        if tx.request.headers.contains_key("accept-charset") {
            out.push(ctx.by_client().report_with(
                &ACCEPT_CHARSET_OBSOLETE,
                "Request carries Accept-Charset, which RFC 9110 §12.5.2 deprecates: UTF-8 is nearly ubiquitous, and the list costs bandwidth and latency and makes passive fingerprinting easier".to_string(),
            ));
        }

        // A response carrying the field is not something §12.5.2 describes, and
        // it forbids one nowhere either -- the same asymmetry §12.5.4 has. The
        // value is still read, because a malformed one is malformed wherever it
        // appears, and it is the server's: attributing it to the client would
        // name the wrong peer to fix it. The deprecation is not raised here,
        // since the sentence retiring the field is about the field a user agent
        // sends.
        if let Some(resp) = &tx.response {
            out.extend(validate(&resp.headers, crate::lint::Party::Server));
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AcceptCharsetValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn run(value: &str) -> Vec<Violation> {
        let tx =
            crate::test_helpers::make_test_transaction_with_headers(&[("accept-charset", value)]);
        crate::test_helpers::run_rule_all(
            &AcceptCharsetValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["accept_charset_valid"]),
        )
    }

    /// A value read as the octets it holds. The whitespace entry is reached by
    /// a SP *inside* a member — `utf 8` — and not by a `CTL`: the header map
    /// refuses every octet below %x20 and %x7F outright, so a value carrying
    /// one cannot be built here at all and arrives only in a capture written
    /// elsewhere. Both octets answer the same entry, which is the one this
    /// reaches.
    fn run_raw(value: &[u8]) -> Vec<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.insert(
            "accept-charset",
            hyper::header::HeaderValue::from_bytes(value).expect("field-content"),
        );
        crate::test_helpers::run_rule_all(
            &AcceptCharsetValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["accept_charset_valid"]),
        )
    }

    fn ids(found: &[Violation]) -> Vec<&str> {
        found.iter().map(|v| v.violation.as_str()).collect()
    }

    /// **The value half, one row per shape the production refuses.**
    ///
    /// Each of these draws nothing on this field before the rule exists and a
    /// finding on a sibling field throughout, which is the whole argument for
    /// the rule: `#( ( token / "*" ) [ weight ] )` is `#( codings [ weight ] )`
    /// with a different name for the primary, so a member malformed here is
    /// malformed there.
    #[rstest]
    #[case("utf-8;", "weight_missing")]
    #[case("utf-8;q=0.5;q=0.8", "weight_duplicated")]
    #[case("utf-8;q=1.5", "qvalue_malformed")]
    #[case("utf-8;q=1.0000", "qvalue_malformed")]
    #[case("utf-8;q = 0.5", "weight_equals_whitespace_forbidden")]
    #[case("utf-8;q =0.5", "weight_equals_whitespace_forbidden")]
    #[case("utf-8;charset=utf-8", "weight_malformed")]
    #[case("utf-8;q", "weight_malformed")]
    #[case("utf-8,,iso-8859-1", "list_member_empty")]
    #[case(";q=0.5", "token_empty")]
    #[case("utf@8", "token_character_forbidden")]
    fn a_member_that_derives_from_nothing_is_named(#[case] value: &str, #[case] id: &str) {
        let found = run(value);
        assert!(
            ids(&found).contains(&id),
            "{value}: {:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// **Every defective member is answered, not the first.** The field states
    /// one preference per position, so a value stating three malformedly is
    /// three preferences the operator has to correct.
    #[test]
    fn every_defective_member_is_reported() {
        let found = run("utf-8;q=x, iso-8859-1;charset=y, us-ascii;q=1;q=1");
        let value_ids: Vec<_> = ids(&found)
            .into_iter()
            .filter(|i| *i != "accept_charset_obsolete")
            .collect();
        assert_eq!(
            value_ids.len(),
            3,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        assert!(value_ids.contains(&"qvalue_malformed"));
        assert!(value_ids.contains(&"weight_malformed"));
        assert!(value_ids.contains(&"weight_duplicated"));
    }

    /// **The `*` is the production's other alternative, not a charset name.**
    /// § 12.5.2 gives it a meaning of its own, so the token scan is not asked
    /// of it — and a weight on it is read like any other member's.
    #[rstest]
    #[case("*")]
    #[case("*;q=0.1")]
    #[case("utf-8, us-ascii;q=0.8, *;q=0.1")]
    #[case("utf-8")]
    #[case("utf-8, iso-8859-1")]
    fn a_legal_value_draws_nothing_about_the_value(#[case] value: &str) {
        let found = run(value);
        let value_ids: Vec<_> = ids(&found)
            .into_iter()
            .filter(|i| *i != "accept_charset_obsolete")
            .collect();
        assert!(
            value_ids.is_empty(),
            "{value}: {:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// An empty field value is not an empty element: `#` generates the
    /// zero-element list, and unlike § 12.5.3 this section gives that no
    /// meaning and forbids nothing, so the line is passed over rather than read
    /// as one member the sender left blank.
    #[test]
    fn an_empty_field_value_is_not_an_empty_member() {
        let found = run("");
        assert_eq!(ids(&found), vec!["accept_charset_obsolete"]);
    }

    /// **One finding for the line however many gaps it holds.** What § 5.6.1.1
    /// forbids generating is an empty *element*, and a line written with three
    /// of them is one list with gaps in it.
    #[test]
    fn a_line_with_several_gaps_is_one_list_with_gaps() {
        let found = run("utf-8,,,iso-8859-1,,us-ascii");
        assert_eq!(
            ids(&found)
                .into_iter()
                .filter(|i| *i == "list_member_empty")
                .count(),
            1,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// **The deprecation answers once per message, not once per line.**
    /// Repeated field lines in one section are one value, so a request writing
    /// two `Accept-Charset` lines carries one deprecated field.
    #[test]
    fn two_field_lines_are_one_deprecated_field() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "accept-charset",
            hyper::header::HeaderValue::from_static("utf-8"),
        );
        tx.request.headers.append(
            "accept-charset",
            hyper::header::HeaderValue::from_static("iso-8859-1;q=0.5"),
        );
        let found = crate::test_helpers::run_rule_all(
            &AcceptCharsetValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["accept_charset_valid"]),
        );
        assert_eq!(ids(&found), vec!["accept_charset_obsolete"]);
    }

    /// **Both lines are read for syntax**, which is the other half of the same
    /// claim: one deprecation finding must not cost the second line's value its
    /// reading.
    #[test]
    fn two_field_lines_are_both_read() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "accept-charset",
            hyper::header::HeaderValue::from_static("utf-8;q=1.5"),
        );
        tx.request.headers.append(
            "accept-charset",
            hyper::header::HeaderValue::from_static("iso-8859-1;q=2.0"),
        );
        let found = crate::test_helpers::run_rule_all(
            &AcceptCharsetValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["accept_charset_valid"]),
        );
        assert_eq!(
            ids(&found)
                .into_iter()
                .filter(|i| *i == "qvalue_malformed")
                .count(),
            2,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// **The deprecation is the request's, and the response's value is the
    /// server's.** § 12.5.2 names a field a user agent sends, so the sentence
    /// retiring it is about that direction; a response carrying one is outside
    /// what the section describes and forbidden by nothing, so its value is
    /// read for syntax and attributed to whoever wrote it. Attributing a
    /// server's malformed value to the client would name the wrong peer to fix
    /// it.
    #[test]
    fn a_response_is_read_for_syntax_and_is_not_deprecated() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("accept-charset", "utf-8;q=1.5")],
        );
        let found = crate::test_helpers::run_rule_all(
            &AcceptCharsetValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["accept_charset_valid"]),
        );
        assert_eq!(ids(&found), vec!["qvalue_malformed"]);
        assert_eq!(found[0].party, Some(crate::lint::Party::Server));
    }

    /// A request's findings are the client's, both halves of them.
    #[test]
    fn a_requests_findings_are_the_clients() {
        let found = run("utf-8;q=1.5");
        assert_eq!(found.len(), 2);
        for v in &found {
            assert_eq!(v.party, Some(crate::lint::Party::Client), "{}", v.violation);
        }
    }

    /// **Every published example draws the entry it is about, and not only the
    /// deprecation.**
    ///
    /// The hazard is particular to this rule and is worth a test of its own:
    /// the field is deprecated, so *every* snippet carrying it draws
    /// `accept_charset_obsolete` — and a suite that judges a non-compliant
    /// example on drawing anything at all would pass all ten of them with every
    /// value reading silently. One example is legitimately about the field
    /// alone; the rest name a value, and this asserts each reaches it.
    #[test]
    fn every_example_about_a_value_reaches_that_value() {
        let expected: &[(&str, Option<&str>)] = &[
            ("iso-8859-5, unicode-1-1;q=0.8", None),
            ("utf-8, *;q=0.1", None),
            ("utf-8;charset=utf-8", Some("weight_malformed")),
            ("utf-8;", Some("weight_missing")),
            ("utf-8;q=0.5;q=0.8", Some("weight_duplicated")),
            ("utf-8;q=1.5", Some("qvalue_malformed")),
            ("utf-8;q = 0.5", Some("weight_equals_whitespace_forbidden")),
            ("utf-8,,iso-8859-1", Some("list_member_empty")),
            (";q=0.5", Some("token_empty")),
            ("utf@8", Some("token_character_forbidden")),
        ];
        let snippets: Vec<String> = AcceptCharsetValid
            .examples()
            .iter()
            .map(|e| {
                e.snippet
                    .rsplit_once("Accept-Charset: ")
                    .expect("every example writes the field")
                    .1
                    .to_string()
            })
            .collect();
        assert_eq!(
            snippets,
            expected
                .iter()
                .map(|(v, _)| v.to_string())
                .collect::<Vec<_>>(),
            "the examples and this table have drifted apart"
        );
        for (value, id) in expected {
            let found = run(value);
            let value_ids: Vec<_> = ids(&found)
                .into_iter()
                .filter(|i| *i != "accept_charset_obsolete")
                .collect();
            match id {
                Some(id) => assert!(
                    value_ids.contains(id),
                    "{value} was published as an example of {id} and drew {value_ids:?}"
                ),
                None => assert!(
                    value_ids.is_empty(),
                    "{value} is an example of the deprecation alone and drew {value_ids:?}"
                ),
            }
            assert!(
                ids(&found).contains(&"accept_charset_obsolete"),
                "{value} carries the field and must draw the deprecation"
            );
        }
    }

    /// § 12.5.2's own example is well formed, and the rule says so — the only
    /// thing wrong with it is the field. Worth pinning because the section
    /// prints it and a reader will try it.
    #[test]
    fn the_sections_own_example_is_a_conforming_value() {
        let found = run("iso-8859-5, unicode-1-1;q=0.8");
        assert_eq!(ids(&found), vec!["accept_charset_obsolete"]);
    }

    /// Every entry this rule declares is one it can emit, which is what the
    /// declarer table is for.
    #[test]
    fn the_declared_entries_are_the_ones_reached() {
        let reached: std::collections::BTreeSet<&str> = [
            "utf-8;",
            "utf-8;q=0.5;q=0.8",
            "utf-8;q=1.5",
            "utf-8;q = 0.5",
            "utf-8;charset=utf-8",
            "utf-8,,iso-8859-1",
            ";q=0.5",
            "utf@8",
        ]
        .iter()
        .flat_map(|v| run(v).into_iter().map(|f| f.violation))
        .chain(run_raw(b"utf 8").into_iter().map(|f| f.violation))
        .map(|s| Box::leak(s.into_boxed_str()) as &str)
        .collect();
        let declared: std::collections::BTreeSet<&str> = DECLARED.iter().map(|d| d.id).collect();
        assert_eq!(
            declared.difference(&reached).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "declared and never reached"
        );
    }
}
