// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::qvalue::{
    QVALUE_MALFORMED, RFC_9110_12_4_2, WEIGHT_DUPLICATED, WEIGHT_EQUALS_WHITESPACE_FORBIDDEN,
    WEIGHT_MALFORMED, WEIGHT_MISSING,
};
use crate::violations::ViolationDef;

/// Nothing this rule reports is about `Accept-Language` alone.
///
/// A weight is § 12.4.2's number and four fields carry it, so a `q=1.5` here
/// and a `q=1.5` in an `Accept` are one defect with one severity. The rest of
/// what the rule says was filed under "the *assembly* this field admits" and
/// read by this rule alone — a `;` with no weight after it, a second weight, a
/// parameter that is not `q` at a field whose grammar has no parameter list.
/// `accept_encoding_parameter_valid` says all three about its own field, in
/// the same order and for the same reason: `#( language-range [ weight ] )`
/// and `#( codings [ weight ] )` put `[ weight ]` after the primary and stop,
/// so the only construct that can be malformed there is the weight. The fifth
/// entry is the weight's spelling rather than its assembly, and it arrived from
/// `te_header_valid`, which reported it while three fields printing the same
/// production called it a known leniency.
static DECLARED: &[&ViolationDef] = &[
    &QVALUE_MALFORMED,
    &WEIGHT_MISSING,
    &WEIGHT_MALFORMED,
    &WEIGHT_DUPLICATED,
    &WEIGHT_EQUALS_WHITESPACE_FORBIDDEN,
];

pub struct AcceptLanguageWeightValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_12_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4",
    note: "Accept-Language: `#( language-range [ weight ] )` — the production that says a range may carry a weight and nothing else. Note that, unlike Accept and Accept-Encoding, this section gives the field no meaning in a response",
};
const RFC_4647_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 4647",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc4647.html#section-2.1",
    note: "Basic Language Range: where `language-range` is defined, by reference from RFC 9110. Its syntax is `language_tag_syntax`'s subject, not this rule's",
};
const RFC_9110_5_6_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
    note: "Recipient Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore. The sender's MUST NOT against generating one is §5.6.1.1's, and `language_tag_syntax` reports it on this field",
};

impl RuleMeta for AcceptLanguageWeightValid {
    fn id(&self) -> &'static str {
        "accept_language_weight_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept-Language Weight Validity")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept-Language` header reads as `#( language-range [ weight ] )`: each member a language range, optionally followed by a weight whose value is a `qvalue` — `0` to `1` with at most three digits after the point.\n\n**There is no parameter list in this field.** A range may carry a weight and nothing else, so `en;charset=utf-8` is reported however well formed the pair looks in isolation. The rule used to check that parameter names were tokens and values were tokens or quoted-strings, which is the parameter grammar of a *different* kind of field; its own SpecRef note said it was following \"the same q/parameter validation semantics used across other headers in this project\".\n\n**Three consequences of the same reading.** `weight` brackets nothing, so `en;` and `en;;q=0.5` are separators introducing a weight that is not there. `[ weight ]` is singular, so `en;q=0.5;q=0.8` is two of it. And a weight is optional — `en, fr` is as conforming as `en;q=1, fr;q=0.8`.\n\n**The language range itself is not checked here, and neither is an empty list element.** Both are `language_tag_syntax`'s subject: it reports an empty range, whitespace inside one, and an over-long subtag, it lets `*` through, and it reports the comma a sender wrote with nothing beside it. One stray comma reported by both rules would be two findings, so this one drops the empty member and claims nothing about it.\n\n**A response's Accept-Language is read, but the spec does not describe one.** This is the asymmetry worth knowing about: §12.5.1 and §12.5.3 each say what `Accept` and `Accept-Encoding` mean when a server sends them in a response, and §12.5.4 says no such thing — it defines a request field and stops. The value is still checked, because a malformed one is malformed wherever it appears, but the finding is about syntax and claims nothing about meaning.\n\n**Whitespace beside the weight's `=` is reported**, and the production is the whole argument: `weight = OWS \";\" OWS \"q=\" qvalue` prints both of its `OWS` *before* `\"q=\"`, which is one string literal with nothing optional inside it. So `q =0.5` is not bad whitespace a recipient parses out — it is characters the construct does not generate, in the one place it has no `OWS` to spare. The value is still trimmed before the number is read, because that is what a recipient does; reporting it is what the *sender* is told.\n\n**The value is read as the octets the sender wrote**, and each is reported by whichever production it landed in. Nothing in this grammar is a quoted-string, so no octet outside visible US-ASCII is legal anywhere in the field — but this rule reads only what follows the `;`, where such an octet fails the `q` name or the `qvalue`. One inside the range is `language_tag_syntax`'s, which reads the same field the same way: the range's characters are deferred to the same place as the range's syntax. Refusing to decode the line reported the octet and put every other defect written beside it out of reach."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_12_5_4,
            RFC_9110_12_4_2,
            RFC_4647_2_1,
            RFC_9110_5_6_1_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// Both halves are read, and that is a fact about this code rather than a
    /// second meaning the spec gives the field — the asymmetry is worth
    /// noticing. §12.5.1 and
    /// §12.5.3 each say what Accept and Accept-Encoding mean *when sent by a
    /// server in a response*, and §12.5.4 says no such thing about
    /// Accept-Language — it defines a request field and stops. A response
    /// carrying one is outside what RFC 9110 describes, so the response arm
    /// here reports syntax and claims nothing about meaning.
    /// cite(RFC 9110 § 12.5.4): "The "Accept-Language" header field can be used by user agents to indicate the set of natural languages that are preferred in the response."
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en-US, fr;q=0.8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the wildcard range, and a weight is optional)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: *;q=0.5, en;q=0.7",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(RFC 9110 \u{a7}12.5.4's own example)"),
                snippet:
                    "GET / HTTP/1.1\nHost: example.com\nAccept-Language: da, en-gb;q=0.8, en;q=0.7",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a qvalue has at most three digits after the point)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a range may carry a weight and nothing else)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;badparam=value",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a well-formed parameter the field still has no room for)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;foo=\"a\\\"b\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no qvalue after the separator)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight there may be at most one of)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=0.5;q=0.8",
            },
        ]
    }
}

impl Rule for AcceptLanguageWeightValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The production the rule is a reading of. A member is a range and at
            // most one weight; nothing else derives from it.
            // cite(RFC 9110 § 12.5.4): "Accept-Language = #( language-range [ weight ] )"
            // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
            let validate_value = |hdr_value: &str| -> Option<Violation> {
                // A comma split with no regard for quoting, which is right rather
                // than merely tolerable: nothing in this grammar is a
                // quoted-string, so there is no quoted comma to protect.
                //
                // Empty list elements are dropped here, and that is an ownership
                // claim rather than a verdict on the value. §5.6.1.1 forbids the
                // sender to generate one and `language_tag_syntax` reports it —
                // that rule walks the same field for the range's own syntax, and
                // one stray comma reported by both would be two findings. What
                // is skipped is the member; what §5.6.1.2 licenses is only a
                // recipient's ignoring of it.
                // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                for member in crate::helpers::list::list_members(hdr_value) {
                    // Each member: language-range [; params]. `OWS`, not
                    // `str::trim`: on a value read one `char` per octet the
                    // wider trim removes %xA0 and %x85, which are `obs-text` —
                    // octets this field admits nowhere, and ones the checks
                    // below would then never see.
                    let mut iter = member.split(';').map(crate::helpers::headers::trim_ows);
                    // The language-range itself is `language_tag_syntax`'s
                    // subject, and that deferral has been checked rather than
                    // assumed: it reports an empty range, whitespace inside one, and
                    // an over-long subtag, and it lets `*` through.
                    let _primary = iter.next().unwrap();

                    // A language-range may carry a weight. That is the whole of what
                    // may follow it — `#( language-range [ weight ] )` has no
                    // parameter list in it, and `weight` is the fixed shape
                    // `OWS ";" OWS "q=" qvalue`. Checking that parameter names are
                    // tokens and values are tokens-or-quoted-strings validated a
                    // grammar this field does not have, and so called
                    // `en;charset=utf-8` well formed.
                    //
                    // The weight is optional — "can be given" — so its absence is
                    // never a finding. What is a finding is something else in its
                    // place, or two of it.
                    // cite(RFC 9110 § 12.5.4): "Each language-range can be given an associated quality value representing an estimate of the user's preference for the languages specified by that range, as defined in Section 12.4.2."
                    let mut weight_seen = false;
                    for param in iter {
                        // Not skipped as an empty parameter slot: there are no
                        // parameter slots, and `weight` brackets nothing, so a `;`
                        // with nothing after it introduces a weight that is absent.
                        if param.is_empty() {
                            return Some(ctx.report_with(
                                &WEIGHT_MISSING,
                                format!(
                                    "Accept-Language member '{}' has a ';' with no weight after it",
                                    member
                                ),
                            ));
                        }
                        // Matched without regard to case because §12.4.2 defines
                        // the parameter that way, and this is the only name the
                        // field admits.
                        // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
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

                        if !name.eq_ignore_ascii_case("q") {
                            return Some(ctx.report_with(&WEIGHT_MALFORMED, format!(
                                    "'{}' is not a weight, and a weight is the only thing an Accept-Language range may carry (member '{}')",
                                    param, member
                                )));
                        }
                        // §12.5.4 brackets one `[ weight ]` after the range,
                        // and the message names it because the entry cannot: the
                        // same bracket is written once per field, and a shared
                        // entry may only cite a sentence every rule declaring it
                        // states.
                        if weight_seen {
                            return Some(ctx.report_with(
                                &WEIGHT_DUPLICATED,
                                format!(
                                    "More than one weight in Accept-Language member '{}': §12.5.4 brackets one",
                                    member
                                ),
                            ));
                        }
                        weight_seen = true;

                        // Not `parameter_equals_whitespace_forbidden`: that
                        // entry answers § 5.6.6's Note about a `parameter`, and
                        // this field has no parameter list for the Note to be
                        // about.
                        if whitespace_beside_equals {
                            return Some(ctx.report_with(&WEIGHT_EQUALS_WHITESPACE_FORBIDDEN, format!(
                                    "Accept-Language member '{}' writes whitespace around the weight's '='; the weight is OWS \";\" OWS \"q=\" qvalue, which admits none there",
                                    member
                                )));
                        }

                        // The name matched and the `=` did not, which is one
                        // literal short of a weight rather than a parameter
                        // missing its value: `"q="` is written as a single
                        // string, so there is no `=` here to be absent from a
                        // pair this field never had.
                        let Some(val) = val_opt else {
                            return Some(ctx.report_with(&WEIGHT_MALFORMED, format!(
                                    "'{}' is not a weight in Accept-Language member '{}': the production writes \"q=\" as one literal and this member stops at the name",
                                    name, member
                                )));
                        };

                        // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
                        if !crate::helpers::qvalue::valid_qvalue(val) {
                            return Some(ctx.report_with(
                                &QVALUE_MALFORMED,
                                format!(
                                    "Invalid qvalue '{}' in Accept-Language member '{}'",
                                    val, member
                                ),
                            ));
                        }
                    }
                }
                None
            };

            // Read as the octets the sender wrote, one `char` per octet, and
            // the hand-off is what makes that safe. Nothing in this grammar is
            // a quoted-string, so an octet outside visible US-ASCII is legal
            // nowhere in the field — but this rule reads only what follows the
            // `;`, and there such an octet fails the `q` name or the `qvalue`.
            // One inside the range is `language_tag_syntax`'s, which reads the
            // same field the same way and reports it there; the deferral of the
            // range's *characters* is the same deferral as the range's syntax.
            // Refusing the whole line reported the octet and hid every other
            // defect written beside it.
            for line in crate::helpers::headers::field_lines_as_written(
                &tx.request.headers,
                "accept-language",
            ) {
                if let Some(v) = validate_value(&line) {
                    return Some(v);
                }
            }

            // A response carrying Accept-Language is not something §12.5.4
            // describes, unlike its two siblings. The value is still read, because
            // a malformed one is malformed wherever it appears and a proxy does see
            // them echoed — but the finding is about syntax and says nothing about
            // what the field would mean here.
            if let Some(resp) = &tx.response {
                for line in crate::helpers::headers::field_lines_as_written(
                    &resp.headers,
                    "accept-language",
                ) {
                    if let Some(v) = validate_value(&line) {
                        return Some(v);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AcceptLanguageWeightValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Four fields, one number. `q=1.5` derives from neither alternative of
    /// § 12.4.2's production wherever it is written, and each rule still names
    /// the field and the member it was written in.
    #[rstest]
    #[case("accept-language", "en;q=1.5")]
    #[case("accept-encoding", "gzip;q=1.5")]
    #[case("accept", "text/plain;q=1.5")]
    #[case("te", "gzip;q=1.5")]
    fn a_weight_is_the_same_defect_in_every_field(#[case] field: &str, #[case] value: &str) {
        let rule: &dyn crate::rules::Rule = match field {
            "accept-language" => &AcceptLanguageWeightValid,
            "accept-encoding" => {
                &super::super::accept_encoding_parameter_valid::AcceptEncodingParameterValid
            }
            "accept" => &super::super::accept_header_media_type_syntax::AcceptHeaderMediaTypeSyntax,
            _ => &super::super::te_header_valid::TeHeaderValid,
        };
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(field, value)]);
        let found = crate::test_helpers::run_rule(
            rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "qvalue_malformed", "{field}: {value}");
        assert!(found.message.contains("1.5"), "{}", found.message);
    }

    /// Four fields, one literal. `"q="` is written as a single ABNF string
    /// with nothing optional inside it and both of `weight`'s `OWS` standing
    /// before it, so whitespace there is the same defect wherever the weight is
    /// carried — and three of these four rules published it as a known leniency
    /// while the fourth reported it.
    #[rstest]
    #[case("accept-language", "en;q =0.5")]
    #[case("accept-language", "en;q= 0.5")]
    #[case("accept-encoding", "gzip;q =0.5")]
    #[case("accept-encoding", "gzip;q= 0.5")]
    #[case("accept", "text/plain;q =0.5")]
    #[case("te", "gzip;q =0.5")]
    fn whitespace_beside_the_weights_equals_is_one_defect_in_every_field(
        #[case] field: &str,
        #[case] value: &str,
    ) {
        let rule: &dyn crate::rules::Rule = match field {
            "accept-language" => &AcceptLanguageWeightValid,
            "accept-encoding" => {
                &super::super::accept_encoding_parameter_valid::AcceptEncodingParameterValid
            }
            "accept" => &super::super::accept_header_media_type_syntax::AcceptHeaderMediaTypeSyntax,
            _ => &super::super::te_header_valid::TeHeaderValid,
        };
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(field, value)]);
        let found = crate::test_helpers::run_rule(
            rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(
            found.violation, "weight_equals_whitespace_forbidden",
            "{field}: {value}"
        );
    }

    /// The other side of that line, and the reason the two ids are two: a
    /// *parameter*'s `=` is § 5.6.6's, whose Note six rules in this tree
    /// publish a leniency about. Only the `q` stopped being lenient.
    #[test]
    fn a_media_range_parameter_keeps_the_leniency_the_weight_lost() {
        let rule = super::super::accept_header_media_type_syntax::AcceptHeaderMediaTypeSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "accept",
            "text/plain;charset = utf-8",
        )]);
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "accept_header_media_type_syntax",
            ]),
        );
        assert!(found.is_none(), "{found:?}");
    }

    /// The assembly around the weight, which this rule's `DECLARED` used to
    /// call its own. Two fields whose production puts `[ weight ]` after the
    /// primary and stops, so the only construct that can go wrong after the
    /// `;` is the weight — and the pair of values in each row is one defect
    /// written twice, not two defects that resemble each other.
    #[rstest]
    #[case("accept-language", "en;", "weight_missing")]
    #[case("accept-encoding", "gzip;", "weight_missing")]
    #[case("accept-language", "en;charset=utf-8", "weight_malformed")]
    #[case("accept-encoding", "gzip;charset=utf-8", "weight_malformed")]
    // `"q="` is one literal, so a member stopping at the name has not written
    // it — the same defect as writing another name entirely.
    #[case("accept-language", "en;q", "weight_malformed")]
    #[case("accept-encoding", "gzip;q", "weight_malformed")]
    #[case("accept-language", "en;q=0.5;q=0.8", "weight_duplicated")]
    #[case("accept-encoding", "gzip;q=0.5;q=0.8", "weight_duplicated")]
    fn the_weights_assembly_is_the_same_defect_in_both_fields(
        #[case] field: &str,
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let rule: &dyn crate::rules::Rule = if field == "accept-language" {
            &AcceptLanguageWeightValid
        } else {
            &super::super::accept_encoding_parameter_valid::AcceptEncodingParameterValid
        };
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(field, value)]);
        let found = crate::test_helpers::run_rule(
            rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, expected, "{field}: {value}");
    }

    #[rstest]
    #[case(Some("en"), false)]
    #[case(Some("en;q=0.8"), false)]
    #[case(Some("zh;q=0"), false)]
    #[case(Some("en-US;q=1.0"), false)]
    #[case(Some("*, en;q=0.5"), false)]
    #[case(Some("en;q=1.0000"), true)]
    #[case(Some("en;q="), true)]
    // A qvalue may end at the point: `0*3DIGIT` admits no digits at all.
    #[case(Some("en;q=0."), false)]
    #[case(Some("en;param=bad value"), true)]
    // A language-range may carry a weight and nothing else, so every one of
    // these is malformed however well formed the pair itself looks.
    #[case(Some("en;charset=utf-8"), true)]
    #[case(Some("en;q=0.5;foo=bar"), true)]
    // `[ weight ]` is singular.
    #[case(Some("en;q=0.5;q=0.8"), true)]
    // `weight` brackets nothing, so a `;` introducing nothing is a defect
    // wherever it sits.
    #[case(Some("en;"), true)]
    #[case(Some("en;;q=0.5"), true)]
    // The RFC's own example, and the forms the grammar does produce.
    #[case(Some("da, en-gb;q=0.8, en;q=0.7"), false)]
    #[case(Some("*;q=0"), false)]
    #[case(Some("en;Q=0.5"), false)]
    #[case(Some(""), false)]
    fn check_request_cases(
        #[case] al: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = al {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
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
                al.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                al.unwrap_or("<none>"),
                v
            );
        }
        Ok(())
    }

    /// An octet outside visible US-ASCII no longer takes the line with it. The
    /// value used to be refused whole — one finding about the octet, and every
    /// other defect on the line unread — so this asserts the part that was
    /// being lost: a weight written badly beside such an octet is reported, and
    /// reported as the weight's defect.
    #[rstest]
    #[case(b"en\xff, fr;q=1.0000")]
    #[case(b"\xff;q=1.0000")]
    fn an_obs_text_octet_does_not_hide_the_weight_beside_it(
        #[case] raw: &[u8],
    ) -> anyhow::Result<()> {
        let rule = AcceptLanguageWeightValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-language", HeaderValue::from_bytes(raw)?);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(v.violation, "qvalue_malformed", "{v:?}");
        Ok(())
    }

    /// The other half of the hand-off, asserted so the deferral is a decision
    /// and not an omission: an octet inside the *range* is nothing this rule
    /// reads. It reports the range's syntax nowhere, so it reports the range's
    /// characters nowhere either — `language_tag_syntax` reads the same field
    /// as written and names the octet there.
    #[test]
    fn an_obs_text_octet_inside_the_range_belongs_to_the_other_rule() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-language", HeaderValue::from_bytes(b"en\xff")?);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hm;
        let history = crate::transaction_history::TransactionHistory::empty();

        assert!(crate::test_helpers::run_rule(
            &AcceptLanguageWeightValid,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "accept_language_weight_valid",
            ]),
        )
        .is_none());
        assert!(crate::test_helpers::run_rule(
            &super::super::language_tag_syntax::LanguageTagSyntax,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]),
        )
        .is_some());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_are_checked() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en, fr;q=0.5"));
        headers.append("accept-language", HeaderValue::from_static("zh;q=1.0000"));

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
    fn response_header_invalid_q_reports_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;q=1.0000")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    /// The response arm reads the octets too, and the line survives there for
    /// the same reason.
    #[test]
    fn a_response_line_with_an_obs_text_octet_is_still_read() -> anyhow::Result<()> {
        let rule = AcceptLanguageWeightValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "accept-language",
            HeaderValue::from_bytes(b"en\xff, fr;q=1.0000")?,
        );
        tx.response.as_mut().unwrap().headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(v.violation, "qvalue_malformed", "{v:?}");
        Ok(())
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates. One Compliant example here was
    /// `en;foo="a\"b"` — published as conforming because the quoted-string is
    /// well formed, when the field has no room for the parameter at all. A
    /// premise this wrong reaches the docs as readily as it reaches the code.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 5] = [
            ("en;q=1.0000", "Invalid qvalue"),
            ("en;badparam=value", "is not a weight"),
            ("en;foo=\"a\\\"b\"", "is not a weight"),
            ("en;q=", "Invalid qvalue"),
            ("en;q=0.5;q=0.8", "More than one weight"),
        ];

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.contains("HTTP/"))
                .map(|l| {
                    let (k, v) = l
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v)
                })
                .collect();
            let al = pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("example has no Accept-Language: {:?}", ex.snippet));
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
                    "rule rejects its Compliant example {al:?}: {found:?}"
                ),
                Compliance::NonCompliant => {
                    let found = found
                        .unwrap_or_else(|| panic!("rule accepts its NonCompliant example {al:?}"));
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == al)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {al:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {al:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// `Accept-Language = #( language-range [ weight ] )` leaves no room for a
    /// `foo` parameter, well formed or not. These asserted the opposite: that a
    /// valid quoted-string value made the member acceptable, and that an
    /// invalid one was the reason to report it. The member is reported either
    /// way, and for the reason that holds for both.
    #[test]
    fn a_parameter_that_is_not_a_weight_is_reported_however_it_is_written() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        for value in [
            "en;foo=\"ok\"",
            "en;foo=\"unterminated",
            "en;foo=\"a\\\"b\"",
            "en;charset=utf-8",
        ] {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", value)]);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            let v = v.unwrap_or_else(|| panic!("{value:?} carries something that is not a weight"));
            assert!(v.message.contains("is not a weight"), "{value:?}: {v:?}");
        }
    }

    #[test]
    fn invalid_param_name_reports_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;b@d=1")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn param_without_value_reports_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;param")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn wildcard_with_q_ok() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "*;q=0.5")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn uppercase_q_parameter_name_is_accepted() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;Q=0.5")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_all_valid_no_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en;q=1.0"));
        headers.append("accept-language", HeaderValue::from_static("fr;q=0.8"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// The empty member is a finding on this field and it is not this rule's.
    /// `language_tag_syntax` reports it — the two rules walk the same list, and
    /// a stray comma answered by both would be one defect counted twice. What
    /// this pins is the silence, so that a later reader meeting the dropped
    /// member here does not conclude the value is clean.
    ///
    /// The weight is still read on every member the sender did write, which is
    /// what makes the silence a deferral rather than a gap.
    #[rstest]
    #[case("en,,de", false)]
    #[case("en, , de", false)]
    #[case(",", false)]
    #[case("en,", false)]
    #[case("en,,de;q=bad", true)]
    fn the_empty_member_belongs_to_the_range_rule(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", value)]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{value:?} drew {v:?}");
    }

    #[test]
    fn needs_no_response() {
        let rule = AcceptLanguageWeightValid;
        assert!(!rule.needs_response());
    }

    #[test]
    fn message_and_id() {
        let rule = AcceptLanguageWeightValid;
        assert_eq!(rule.id(), "accept_language_weight_valid");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "accept_language_weight_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
