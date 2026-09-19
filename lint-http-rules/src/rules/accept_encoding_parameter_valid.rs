// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
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

pub struct AcceptEncodingParameterValid;

/// The `token` pair, and nothing else in this rule belongs to a subject.
///
/// `content-coding = token` is the one production this field borrows whole, and
/// § 8.4.1 states it here the way RFC 6797 § 6.1 states it for a directive
/// name: the field's own section says *which* production, and § 5.6.2 says what
/// the production is. So a `@` in a coding name draws the same id it draws in a
/// `Content-Encoding`, a `TE`, a field name or a method.
///
/// **Everything else this rule reports is about the member's shape**, and
/// `codings [ weight ]` owns all of it: a separator introducing a weight that
/// is not there, two of something there may be at most one of, a member whose
/// non-optional half is missing, and a `name=value` pair no derivation of the
/// field produces. Three of those four are the *weight's* residue rather than
/// this field's, which is why they now draw the ids
/// `accept_language_weight_valid` draws: `#( codings [ weight ] )` and
/// `#( language-range [ weight ] )` put `[ weight ]` after the primary and stop,
/// so in both fields the only construct that can be malformed after the `;` is
/// the weight. What is left as this rule's own is the fourth — a member that is
/// all weight and no coding — and it turns out not to be this rule's either.
/// All three of `codings`' alternatives have a one-character floor: a
/// `content-coding` is a `token`, `identity` is one, and `*` is a single
/// `tchar`. So an empty primary derives from none of them for the arithmetic
/// reason `token_empty` already names, and the rule declares nothing of its own
/// at all. `weight_equals_whitespace_forbidden` is the same borrowing one step
/// further out: the spelling of the weight rather than the shape of the member,
/// and this field's `description()` called it a known leniency while
/// `te_header_valid` reported it against the identical production.
static DECLARED: &[&ViolationDef] = &[
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
const RFC_9110_12_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
    note: "Accept-Encoding: `#( codings [ weight ] )` — the production that says a coding may carry a weight and nothing else. Also the three `codings` alternatives, the meaning of an empty field value, and the meaning of the field in a response",
};
const RFC_9110_8_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1",
    note: "Content Codings: `content-coding = token`, which is what the character check on each coding enforces",
};
const RFC_9110_5_6_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
    note: "Recipient Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore, and the meaning of a field value that holds no element at all",
};

impl RuleMeta for AcceptEncodingParameterValid {
    fn id(&self) -> &'static str {
        "accept_encoding_parameter_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept-Encoding Parameter Validity")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept-Encoding` header reads as `#( codings [ weight ] )`: each member a content coding, the literal `identity`, or the literal `*`, optionally followed by a weight.\n\n**The rule's name is a little wrong, and the reason is the point.** `Accept-Encoding` has no parameter list. A coding may carry a `weight` — `OWS \";\" OWS \"q=\" qvalue` — and nothing else, so there is no `name=value` grammar here to be well formed. What this rule checks is that nothing other than a weight appears: `gzip;charset=utf-8` and `gzip;foo=\"a;b\"` are reported, however well formed the pair looks in isolation, because no derivation of this field produces them.\n\n**Three consequences of the same reading.** `weight` brackets nothing, so `gzip;` is a separator introducing a weight that is not there. `[ weight ]` is singular, so `gzip;q=0.5;q=0.8` is two of something there may be at most one of. And `codings` is not optional, so `;q=0.5` is a member with no coding.\n\n**A weight is a MAY**, so its absence is never reported; `gzip, br` is as conforming as `gzip;q=1.0, br;q=0.5`. When present it must be a `qvalue`: `0` to `1` with at most three digits after the point.\n\n**Both directions are read.** A request states what codings a response may use; a response, per §12.5.3, says what the resource was willing to accept — most often in a 415 (Unsupported Media Type), and evaluated the same way.\n\n**An empty field value is not reported, and an empty list element is.** §12.5.3 gives the empty value a meaning of its own — the user agent wants no content coding at all — and the `#` construct generates it. An empty *element* is a different value: §5.6.1.2 expands `#element` with every position bracketed and tells a recipient to ignore what that admits, while §5.6.1.1 expands the same construct for a sender with nothing bracketed and forbids generating one. So `gzip,,br` and `gzip,` are commas the sender may not write, and this rule used to read the field through the recipient's walk, which dropped them before any check could see them.\n\n**Whitespace beside the weight's `=` is reported.** The production spells the weight as the literal text `\"q=\"` rather than as a parameter with a name and a separator, and both `OWS` it prints stand before that literal — so there is no room in it for the space at all, and `gzip;q =0.5` is characters the construct does not generate rather than whitespace a recipient parses out. The value is still trimmed before the number is read, because that is what a recipient does; reporting it is what the *sender* is told.\n\n**The value is read as the octets the sender wrote**, and each is reported by the production it landed in. There are no quoted-strings in this field — a member is a `token`, one of two literals, and the weight's fixed text — so no octet outside visible US-ASCII is legal anywhere in it: one in a coding name is the `token`'s defect, one in a weight fails the `q` name or the `qvalue`. Refusing to decode the line named the octet and put every other defect written beside it out of reach."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_12_5_3,
            RFC_9110_12_4_2,
            RFC_9110_8_4_1,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_9110_5_6_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// Both directions carry the field with a meaning of its own: a request
    /// states what codings a response may use, a response what the resource was
    /// willing to accept. §12.5.3 defines the two readings and gives them the
    /// same syntax, which is why one grammar reads both — and why the peer
    /// answerable for a defect is the one whose section it was read from, not a
    /// single presumption for the file. Presuming the client made a malformed
    /// response `Accept-Encoding` the client's defect, which is a claim about
    /// text the client never wrote.
    /// cite(RFC 9110 § 12.5.3): "When sent by a user agent in a request, Accept-Encoding indicates the content codings acceptable in a response."
    /// cite(RFC 9110 § 12.5.3): "When the Accept-Encoding header field is present in a response, it indicates what content codings the resource was willing to accept in the associated request."
    /// cite(RFC 9110 § 12.5.3): "The field value is evaluated the same way as in a request."
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=0.8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: br;q=1.0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(wildcard with q)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: *;q=0.5, gzip;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid q precision)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid coding token)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip@;q=0.5",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing q value)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an empty value asks for no coding at all)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a coding may carry a weight and nothing else)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight there may be at most one of)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=0.5;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a separator introducing a weight that is not there)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;",
            },
        ]
    }
}

impl Rule for AcceptEncodingParameterValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Each section is read on its own, the finding it yields is kept, and it
        // is blamed on the peer whose section it was read from. §12.5.3 gives
        // the response's `Accept-Encoding` a meaning of its own — what the
        // resource was willing to accept — so the server wrote it, and a defect
        // in it is the server's. Reading the request first and stopping there
        // meant a malformed value in a 415, which is where the field most often
        // appears in a response, was never read at all.
        let mut out = Vec::new();
        {
            // The production the whole rule is a reading of. Two things about it
            // decide almost every branch below: a member is a coding and at most
            // one weight, and `codings` has exactly three alternatives.
            // cite(RFC 9110 § 12.5.3): "Accept-Encoding  = #( codings [ weight ] ) codings          = content-coding / "identity" / "*""
            // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
            let check_all = |headers: &hyper::HeaderMap,
                             party: crate::lint::Party|
             -> Option<Violation> {
                // Read as the octets the sender wrote, one `char` per octet.
                // There are no quoted-strings anywhere in this field — a member
                // is a `token`, one of two literals, and the weight's fixed
                // text — so no octet outside visible US-ASCII is legal in it,
                // and every one of them lands inside a production that already
                // has an id for it. Refusing the whole line named the octet and
                // took every other defect written beside it out of reach.
                for line in
                    crate::helpers::headers::field_lines_as_written(headers, "accept-encoding")
                {
                    let val = line.as_str();
                    // An empty field value is not an empty element, and §12.5.3
                    // gives it a meaning of its own: the user agent wants no
                    // content coding at all. The `#` construct generates that
                    // value, so the line is passed over rather than read as one
                    // member the sender left blank.
                    // cite(RFC 9110 § 12.5.3): "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response."
                    // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
                    // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                    if crate::helpers::headers::trim_ows(val).is_empty() {
                        continue;
                    }
                    // A comma split with no regard for quoting, which is
                    // correct here rather than merely tolerable: nothing in
                    // this field's grammar is a quoted-string, so there is no
                    // quoted comma for a quote-aware splitter to protect.
                    //
                    // The walk keeps the empty member, and that is the whole
                    // difference between the two sentences the `#` construct
                    // carries. §5.6.1.2's expansion brackets every position and
                    // tells a *recipient* to ignore what that admits; §5.6.1.1
                    // expands the same construct for the sender with nothing
                    // bracketed, and forbids generating the element. Reading
                    // this field through the recipient's walk dropped the comma
                    // before any check could see it, so `gzip,,br` — the value
                    // the catalogue's list subject prints first among the ones
                    // this defect is named for — reported nothing.
                    // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
                    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                    for part in crate::helpers::list::sender_list_members(val) {
                        if part.is_empty() {
                            return Some(ctx.by(party).report_with(
                                &LIST_MEMBER_EMPTY,
                                format!(
                                    "Accept-Encoding holds an empty list element; the field line reads '{val}'. Every position in `#( codings [ weight ] )` holds a coding, and a comma with nothing beside it holds none"
                                ),
                            ));
                        }
                        // Split into token and optional params
                        let mut iter =
                            crate::helpers::list::split_semicolons_respecting_quotes(part)
                                .into_iter();
                        if let Some(primary) = iter.next() {
                            // `codings` is a content-coding, the literal "identity",
                            // or the literal "*", and the first two of those are
                            // tokens. A token is one or more characters, which a
                            // scan for an invalid character cannot tell you: an
                            // empty string has no invalid character in it, so
                            // `;q=0.5` — a member that is all weight and no coding —
                            // passed on exactly that reasoning.
                            //
                            // The asterisk is exempted from the token check
                            // because it is one of the three alternatives, not a
                            // coding name; "identity" needs no exemption, being
                            // a token like any other.
                            // cite(RFC 9110 § 8.4.1): "content-coding   = token"
                            // cite(RFC 9110 § 12.5.3): "The asterisk "*" symbol in an Accept-Encoding field matches any available content coding not explicitly listed in the field."
                            // cite(RFC 9110 § 12.5.3): "An "identity" token is used as a synonym for "no encoding" in order to communicate when no encoding is preferred."
                            if primary != "*" {
                                // The `1*tchar` floor, which all three
                                // alternatives share: a `content-coding` is a
                                // `token`, `identity` is one, and `*` is a
                                // single `tchar`. So a member that begins at
                                // the `;` derives from none of them for one
                                // arithmetic reason, and the id names that
                                // reason rather than this field.
                                if primary.is_empty() {
                                    return Some(ctx.by(party).report_with(
                                        &TOKEN_EMPTY,
                                        format!(
                                            "Empty content-coding in Accept-Encoding member '{}'",
                                            part
                                        ),
                                    ));
                                }
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(primary)
                                {
                                    return Some(ctx.by(party).report_with(
                                        token_character(c),
                                        format!("Invalid token '{}' in Accept-Encoding header", c),
                                    ));
                                }
                            }

                            // Everything after the coding must be a weight. There is
                            // no parameter list here to be well formed — the whole
                            // member is `codings [ weight ]`, and `weight` is the
                            // fixed shape `OWS ";" OWS "q=" qvalue`. Validating
                            // arbitrary `name=value` pairs answered a question this
                            // field does not ask, and answered it in the direction
                            // that matters: `gzip;charset=utf-8` was called well
                            // formed, when nothing in the grammar produces it.
                            //
                            // The weight is a MAY, so its absence is never a
                            // finding; what is a finding is anything else in
                            // its place, or two of it.
                            // cite(RFC 9110 § 12.5.3): "Each codings value MAY be given an associated quality value (weight) representing the preference for that encoding, as defined in Section 12.4.2."
                            let mut weight_seen = false;
                            for param in iter {
                                // Not skipped as an empty parameter slot, because
                                // there are no parameter slots. `weight` brackets
                                // nothing, so a `;` with nothing after it is a
                                // separator introducing a weight that is not there
                                // — whether it sits at the end of the member or
                                // between two others.
                                if param.is_empty() {
                                    return Some(ctx.by(party).report_with(&WEIGHT_MISSING, format!(
                                        "Accept-Encoding member '{}' has a ';' with no weight after it",
                                        part
                                    )));
                                }

                                // The name is matched without regard to case
                                // because §12.4.2 defines the parameter that
                                // way, and this is the only name the field
                                // admits.
                                // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
                                // `OWS`, not `str::trim`: on a value read one
                                // `char` per octet the wider trim removes %xA0
                                // and %x85, which are `obs-text` — an octet
                                // this field admits nowhere, and one the checks
                                // below would then never see.
                                let mut nv = param.splitn(2, '=');
                                let raw_name = nv.next().unwrap();
                                let raw_value = nv.next();
                                let name = crate::helpers::headers::trim_ows(raw_name);
                                let val = raw_value.map(crate::helpers::headers::trim_ows);
                                // Trimming is what a recipient does to find the
                                // weight; whether a sender may write the
                                // whitespace is a separate question, and the
                                // production answers it. Both `OWS` it prints
                                // stand before `"q="`, which is one string
                                // literal with nothing optional inside it.
                                let whitespace_beside_equals = name.len() != raw_name.len()
                                    || raw_value
                                        .is_some_and(|v| val.is_some_and(|t| t.len() != v.len()));

                                if !name.eq_ignore_ascii_case("q") {
                                    return Some(ctx.by(party).report_with(&WEIGHT_MALFORMED, format!(
                                        "'{}' is not a weight, and a weight is the only thing an Accept-Encoding coding may carry (member '{}')",
                                        param, part
                                    )));
                                }
                                // §12.5.3 brackets one `[ weight ]` after the
                                // codings, and the message names it because the
                                // entry cannot: the same bracket is written once
                                // per field, and a shared entry may only cite a
                                // sentence every rule declaring it states.
                                if weight_seen {
                                    return Some(ctx.by(party).report_with(
                                        &WEIGHT_DUPLICATED,
                                        format!(
                                            "More than one weight in Accept-Encoding member '{}': §12.5.3 brackets one",
                                            part
                                        ),
                                    ));
                                }
                                weight_seen = true;

                                // Not
                                // `parameter_equals_whitespace_forbidden`: that
                                // entry answers § 5.6.6's Note about a
                                // `parameter`, and this field has no parameter
                                // list for the Note to be about.
                                if whitespace_beside_equals {
                                    return Some(ctx.by(party).report_with(&WEIGHT_EQUALS_WHITESPACE_FORBIDDEN, format!(
                                        "Accept-Encoding member '{}' writes whitespace around the weight's '='; the weight is OWS \";\" OWS \"q=\" qvalue, which admits none there",
                                        part
                                    )));
                                }

                                // The name matched and the `=` did not, which is
                                // one literal short of a weight rather than a
                                // parameter missing its value: `"q="` is written
                                // as a single string, so there is no `=` here to
                                // be absent from a pair this field never had.
                                let Some(v) = val else {
                                    return Some(ctx.by(party).report_with(&WEIGHT_MALFORMED, format!(
                                        "'{}' is not a weight in Accept-Encoding member '{}': the production writes \"q=\" as one literal and this member stops at the name",
                                        name, part
                                    )));
                                };

                                // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
                                if !crate::helpers::qvalue::valid_qvalue(v) {
                                    return Some(ctx.by(party).report_with(
                                        &QVALUE_MALFORMED,
                                        format!(
                                            "Invalid qvalue '{}' in Accept-Encoding member '{}'",
                                            v, part
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
                None
            };

            // A response's Accept-Encoding is not a stray request field: §12.5.3
            // gives it a meaning of its own — what the resource was willing to
            // accept — and says its value is evaluated the same way. Only the
            // request was ever read, so a malformed one in a 415 response, which is
            // where the field most often appears, went unchecked.
            out.extend(check_all(&tx.request.headers, crate::lint::Party::Client));
            if let Some(resp) = &tx.response {
                out.extend(check_all(&resp.headers, crate::lint::Party::Server));
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AcceptEncodingParameterValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("gzip"), false)]
    #[case(Some("gzip;q=0.8"), false)]
    #[case(Some("br;q=1.0"), false)]
    #[case(Some("*, gzip;q=0.5"), false)]
    #[case(Some("gzip;q=0"), false)]
    #[case(Some("gzip;q=0.123"), false)]
    #[case(Some("gzip;q=1.000"), false)]
    #[case(Some("gzip;q=1"), false)]
    #[case(Some("gzip;Q=0.5"), false)]
    #[case(Some("gzip;q=1.0000"), true)]
    #[case(Some("x!bad;q=0.5"), false)]
    #[case(Some("gzip;q="), true)]
    #[case(Some("gzip; q=not-a-number"), true)]
    // A qvalue may end at the point: `0*3DIGIT` admits no digits at all.
    #[case(Some("gzip;q=0."), false)]
    #[case(Some("gzip;q=01.0"), true)]
    #[case(Some("gzip;q=0.1234"), true)]
    fn check_request_cases(#[case] ae: Option<&str>, #[case] expect_violation: bool) {
        let rule = AcceptEncodingParameterValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_encoding_parameter_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        }
    }

    /// An octet outside visible US-ASCII is still reported, and now by the
    /// production it landed in rather than by a claim about the whole line.
    /// The second and third rows are what the old whole-line refusal cost: a
    /// defect written *beside* such an octet was never reached.
    #[rstest]
    #[case(b"\xff", "token_character_forbidden")]
    #[case(b"gzip\xff, br;q=1.0000", "token_character_forbidden")]
    #[case(b"br;q=1.0000, gzip\xff", "qvalue_malformed")]
    fn an_obs_text_octet_is_the_defect_of_wherever_it_sits(
        #[case] raw: &[u8],
        #[case] expected: &str,
    ) -> anyhow::Result<()> {
        let rule = AcceptEncodingParameterValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-encoding", HeaderValue::from_bytes(raw)?);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_encoding_parameter_valid",
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(v.violation, expected, "{v:?}");
        Ok(())
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = AcceptEncodingParameterValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 6] = [
            ("gzip;q=1.0000", "Invalid qvalue"),
            ("gzip@;q=0.5", "Invalid token"),
            ("gzip;q=", "Invalid qvalue"),
            ("gzip;charset=utf-8", "is not a weight"),
            ("gzip;q=0.5;q=0.8", "More than one weight"),
            ("gzip;", "no weight after it"),
        ];

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.contains("HTTP/"))
                .map(|l| {
                    let (k, v) = l
                        .split_once(':')
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v.trim())
                })
                .collect();
            let ae = pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("example has no Accept-Encoding: {:?}", ex.snippet));
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == ae)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {ae:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {ae:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// §12.5.3 gives a response's Accept-Encoding a meaning of its own — what
    /// the resource was willing to accept — and says its value is evaluated the
    /// same way as in a request. A 415 is where the field most often appears,
    /// and only the request was ever read.
    #[rstest]
    #[case("gzip;q=1.0000", true)]
    #[case("gzip;charset=utf-8", true)]
    #[case("gzip, br;q=0.5", false)]
    fn accept_encoding_in_a_response_is_read_too(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = AcceptEncodingParameterValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(415, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", value)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{value:?} -> {v:?}");
    }

    /// `Accept-Encoding = #( codings [ weight ] )`. A coding may carry a weight
    /// and nothing else, so every `param=` case below is malformed however
    /// well formed the pair looks — which is what these cases used to assert
    /// the opposite of. A well-formed parameter of a kind the field has no room
    /// for is still a defect; it just is not a *parameter* defect.
    #[rstest]
    #[case(Some("gzip;param=token"), true)]
    #[case(Some("gzip;param=\"ok\""), true)]
    #[case(Some("gzip;param=\"a;b\""), true)]
    #[case(Some("gzip;param=bad value"), true)]
    #[case(Some("gzip;param=\"unterminated"), true)]
    #[case(Some("gzip;#=1"), true)]
    #[case(Some("*;param=token"), true)]
    #[case(Some("gzip;param=\"a\\\"b\""), true)]
    // `weight` brackets nothing, so a `;` with no weight after it is a
    // separator introducing something that is not there.
    #[case(Some("gzip;"), true)]
    #[case(Some("gzip; ;q=0.8"), true)]
    // The same defect in the middle of a member rather than at its end. The
    // message used to say the member "ends in ';'", which this one does not.
    #[case(Some("gzip;;q=0.5"), true)]
    #[case(Some("gzip;q=0.5;"), true)]
    #[case(Some("gzip;param"), true)]
    #[case(Some("gzip;bad name=1"), true)]
    #[case(Some("gzip;q=1.0000, br;q=1.0"), true)]
    #[case(Some("gzip;q=1.0000, x!bad;q=0.5"), true)]
    #[case(Some("gzip@;q=0.5"), true)]
    #[case(Some("gzip;param=bad@val"), true)]
    // A member that is all weight and no coding: `codings` is not optional, and
    // a token is one or more characters — which a scan for an *invalid*
    // character can never notice.
    #[case(Some(";q=0.5"), true)]
    // At most one weight; `[ weight ]` is singular.
    #[case(Some("gzip;q=0.5;q=0.8"), true)]
    // The forms the grammar does produce, including the RFC's own examples.
    #[case(Some("compress, gzip"), false)]
    #[case(Some("compress;q=0.5, gzip;q=1.0"), false)]
    #[case(Some("gzip;q=1.0, identity; q=0.5, *;q=0"), false)]
    #[case(Some("*"), false)]
    // An empty field value is legal, and §12.5.3 gives it a meaning: no content
    // coding is wanted at all. An empty *element* is a comma the sender wrote
    // with nothing beside it, which §5.6.1.1 forbids outright — the walk this
    // rule used to read the field with dropped it, on §5.6.1.2's instruction to
    // a recipient.
    #[case(Some(""), false)]
    #[case(Some("   "), false)]
    #[case(Some("gzip,,br"), true)]
    #[case(Some("gzip, , br"), true)]
    #[case(Some("gzip,"), true)]
    #[case(Some(",gzip"), true)]
    #[case(Some(","), true)]
    fn check_additional_parameter_cases(#[case] ae: Option<&str>, #[case] expect_violation: bool) {
        let rule = AcceptEncodingParameterValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_encoding_parameter_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_are_checked() {
        let rule = AcceptEncodingParameterValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_encoding_parameter_valid",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-encoding", HeaderValue::from_static("gzip"));
        headers.append("accept-encoding", HeaderValue::from_static("br;q=1.0000"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "accept_encoding_parameter_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
