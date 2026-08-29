// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, parse_token_bws_word, trim_ows};
use crate::helpers::list::{list_members_as_written, split_semicolons_respecting_quotes};
use crate::helpers::shown::shown_in_finding;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct PreferHeaderValid;

/// What RFC 7240 § 4's own productions admit after a preference's `=`, for the
/// four preferences this document defines — and nothing for any other name.
///
/// The registry the field points at is open, so a name this function does not
/// know is an extension rather than a defect: the value a registered preference
/// admits is written in *its own* registration, which is where a rule holding
/// only RFC 7240 cannot read it. § 2 says what a server does with a preference
/// it cannot place, and it is not to complain.
///
/// cite(RFC 7240 § 4): "The following subsections define an initial set of preferences."
/// cite(RFC 7240 § 5.1): "Value: (An enumeration or description of possible values for the"
/// cite(RFC 7240 § 2): "A server that does not recognize or is unable to comply with particular preference tokens in the Prefer header field of a request MUST ignore those tokens and continue processing instead of signaling an error."
fn defined_value_defect(name: &str, value: Option<&str>) -> Option<String> {
    match name {
        // The production is the token and nothing else — there is no `=` in it
        // for a value to follow.
        //
        // cite(RFC 7240 § 4.1): "respond-async = "respond-async""
        "respond-async" => value.map(|v| {
            format!(
                "carries the value '{}', where its own production is the token alone",
                shown_in_finding(v)
            )
        }),
        // cite(RFC 7240 § 4.2): "return = "return" BWS "=" BWS ("representation" / "minimal")"
        "return" => one_of(value, &["representation", "minimal"]),
        // cite(RFC 7240 § 4.4): "handling = "handling" BWS "=" BWS ("strict" / "lenient")"
        "handling" => one_of(value, &["strict", "lenient"]),
        // cite(RFC 7240 § 4.3): "wait = "wait" BWS "=" BWS delta-seconds"
        "wait" => match value {
            None => Some("carries no value, where its own production requires one".to_string()),
            // `delta-seconds` is a count of seconds and admits no sign, no
            // decimal point and no whitespace, so `wait=-1` and `wait=1.5` name
            // no length of time. RFC 7240 § 1.1 takes the rule from RFC 7231
            // § 8.1.3, a section that does not contain it; the live definition
            // is below.
            //
            // cite(RFC 9111 § 1.2.2, label: delta-seconds grammar): "delta-seconds  = 1*DIGIT"
            Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => None,
            Some(v) => Some(format!(
                "carries the value '{}', which is not a delta-seconds (1*DIGIT)",
                shown_in_finding(v)
            )),
        },
        _ => None,
    }
}

/// A preference whose own production writes an alternation of literals.
///
/// The comparison folds case because that is what the notation says these
/// literals mean, not as a tolerance: an ABNF quoted string matches any case.
/// RFC 7240 § 2's rule that *values* are case sensitive decides a different
/// question — whether two values written in two messages are the same value —
/// and `preference_applied_header_valid` is the rule that asks it.
///
/// cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
fn one_of(value: Option<&str>, admitted: &'static [&'static str]) -> Option<String> {
    let Some(v) = value else {
        return Some("carries no value, where its own production requires one".to_string());
    };
    if admitted.iter().any(|a| v.eq_ignore_ascii_case(a)) {
        return None;
    }
    Some(format!(
        "carries the value '{}', where its own production admits only {}",
        shown_in_finding(v),
        admitted
            .iter()
            .map(|a| format!("\"{}\"", a))
            .collect::<Vec<_>>()
            .join(" or ")
    ))
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_7240_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
    note: "`Prefer` — the grammar, the equivalence of several field lines with one, the equivalence of an empty value with no value, the case rules for names and values, the SHOULD NOT against repeating a token, and the server's MUST to ignore a preference it does not recognize",
};
const RFC_7240_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-4",
    note: "The four preferences this document defines, each with its own production: `respond-async` (§4.1), `return` (§4.2), `wait` (§4.3) and `handling` (§4.4). §4.2 and §4.4 add that the two values of `return` and of `handling` are mutually exclusive",
};
const RFC_7240_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-5.1",
    note: "The \"HTTP Preferences\" registry is open under Specification Required, and a registration carries its own enumeration of admitted values — which is why a preference RFC 7240 does not define has its value left unjudged here",
};
const RFC_7240_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-1.1",
    note: "Where `token`, `word`, `OWS`, `BWS`, the `#rule` extension and `delta-seconds` come from. The named sources are RFC 7230 and RFC 7231, which RFC 9110 obsoletes; `word` is the one name RFC 9110 did not keep, and the `delta-seconds` pointer is wrong twice over — RFC 7231 §8.1.3 is a registration procedure, and RFC 7231 does not define `delta-seconds` anywhere. It was RFC 7234 §1.2.1's, and the live definition is RFC 9111 §1.2.2",
};
const RFC_9110_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
    note: "The MUST NOT on generating a protocol element that does not match its ABNF — what makes a value outside a §4 production a finding, since RFC 7240 writes those productions and states no requirement about them",
};
const RFC_9110_5_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
    note: "The `#rule` extension: §5.6.1.1 forbids the sender an empty list element, §5.6.1.2 prints the values a `1#` production rejects for having no non-empty member",
};
const RFC_9110_5_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
    note: "`BWS`: a recipient must remove it before interpreting the element, and a sender must not have written it — both directions are read at the `=` in `preference` and in `parameter`",
};
const RFC_9111_1_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("1.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2",
    note: "`delta-seconds = 1*DIGIT` — what the `wait` preference's value has to be",
};
const RFC_5234_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5234",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3",
    note: "An ABNF string literal matches any case, which is why `return=Minimal` is not reported against §4.2's `\"minimal\"`",
};

impl Rule for PreferHeaderValid {
    fn id(&self) -> &'static str {
        "prefer_header_valid"
    }

    /// A request header field, and every sentence below measures the client
    /// that wrote it. `Client` is what lets the rule speak on a capture whose
    /// upstream never answered, which is exactly a request-only lint.
    ///
    /// cite(RFC 7240 § 2): "The Prefer request header field is used to indicate that particular server behaviors are preferred by the client but are not required for successful completion of the request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            let violation = |message: String| Some(self.violation(ctx.severity, message));

            // Read as octets, one `char` each, and joined across the field's lines.
            // Both halves are load-bearing here. A `word` may be a `quoted-string`,
            // `qdtext` admits `obs-text`, and `HeaderValue::to_str` refuses every
            // octet above %x7E — so the decode this loop used to open with reported
            // `Prefer: foo="café"` as invalid while calling it "non-UTF8", which is
            // wrong about the value twice over. And the document says a client may
            // spread its preferences over several field lines, so a member written
            // across a boundary is one member rather than two unreadable halves.
            //
            // cite(RFC 7240 § 2): "A client MAY use multiple instances of the Prefer header field in a single message, or it MAY use a single Prefer header field with multiple comma-separated preference tokens."
            // cite(RFC 7240 § 2): "If multiple Prefer header fields are used, it is equivalent to a single Prefer header field with the comma-separated concatenation of all of the tokens."
            let value = combined_field_value_as_written(&tx.request.headers, "prefer")?;

            // The `,` inside a `quoted-string` is `qdtext` and not a separator,
            // which is why the split is quote-aware: `foo="a,b"` is one member
            // carrying one value, and the naive split this replaced reported both
            // halves of it.
            //
            // cite(RFC 7240 § 2): "Prefer     = "Prefer" ":" 1#preference"
            let members = list_members_as_written(&value);

            // `1#` sets a floor, and the floor counts *non-empty* elements — so
            // `Prefer:`, `Prefer: ,` and `Prefer: ,   ,` are three spellings of one
            // defect. They are the three values § 5.6.1.2's worked example prints
            // for exactly this cardinality, and the last two drew nothing from any
            // rule in the catalogue before this one.
            //
            // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
            // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
            if members.iter().all(|m| m.is_empty()) {
                return violation(
                    "Prefer header states no preference; its value is 1#preference, which requires at least one non-empty member".into(),
                );
            }

            // An empty element beside a real one is the other half of the same
            // grammar and a different requirement: § 5.6.1.2 makes a recipient
            // accept it, § 5.6.1.1 forbids the sender writing it. This rule measures
            // the sender.
            //
            // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
            if members.iter().any(|m| m.is_empty()) {
                return violation(format!(
                    "Prefer header contains an empty list element: '{}'",
                    shown_in_finding(&value)
                ));
            }

            // The names this request has already used, lowercased, in the order the
            // client wrote them.
            let mut seen: Vec<String> = Vec::new();

            // No member below is empty: the two checks above return on an empty list
            // and on an empty element, so a filter here would be an arm no input can
            // reach. The neighbouring `Preference-Applied` rule still carries one.
            for member in members.iter() {
                // A preference is a name-and-value followed by any number of
                // parameters, so only the part before the first top-level `;` is the
                // preference itself. A `;` inside the `word`'s quoted-string is
                // `qdtext` and not a separator, which is why this search is
                // quote-aware too — `foo="a;b"` was being reported for parameters it
                // does not have.
                //
                // cite(RFC 7240 § 2): "preference = token [ BWS "=" BWS word ]"
                // cite(RFC 7240 § 2): "*( OWS ";" [ OWS parameter ] )"
                let mut segments = split_semicolons_respecting_quotes(member).into_iter();
                let first = segments.next().unwrap_or("");

                let parsed = match parse_token_bws_word(first) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        return violation(format!(
                            "Prefer member '{}' does not match preference: {}",
                            shown_in_finding(member),
                            e
                        ))
                    }
                };

                // The `BWS` in the production is why the parse trims around the `=`
                // at all — a recipient is required to. The sender is required not to
                // have written it, and that half was going unsaid because the trim
                // it licenses happens first and leaves nothing behind to look at.
                //
                // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
                // cite(RFC 9110 § 5.6.3): "A recipient MUST parse for such bad whitespace and remove it before interpreting the protocol element."
                if parsed.bws {
                    return violation(format!(
                        "Prefer member '{}' has whitespace around its '='; the grammar admits BWS there only for historical reasons",
                        shown_in_finding(member)
                    ));
                }

                // `foo=""` is not a preference carrying the empty string, it is the
                // same statement as `foo` — the document prints all three spellings
                // side by side. Normalising here is what stops the value checks
                // below from measuring `""` against a production's literals.
                //
                // cite(RFC 7240 § 2): "Empty or zero-length values on both the preference token and within parameters are equivalent to no value being specified at all."
                let value_of = parsed.value.as_deref().filter(|v| !v.is_empty());

                // cite(RFC 7240 § 2): "For both preference token names and parameter names, comparison is case insensitive while values are case sensitive regardless of whether token or quoted-string values are used."
                let name = parsed.name.to_ascii_lowercase();

                // A member can match `preference` and still not match the production
                // for the preference it names, and that is what § 2.2 makes a
                // finding rather than a curiosity. This is the only sentence in
                // reach that says so: RFC 7240 states no requirement of its own
                // about a value, it writes the grammar and leaves it there.
                //
                // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
                // `parsed.name` reaches the message unescaped where every value
                // around it goes through [`shown_in_finding`], and the difference is
                // not an oversight: the parse returns a name only after finding
                // every octet in it to be a `tchar`, which is visible US-ASCII. A
                // `word`'s content has no such guarantee — `qdtext` admits HTAB and
                // `obs-text`.
                if let Some(defect) = defined_value_defect(&name, value_of) {
                    return violation(format!(
                        "Prefer names the '{}' preference, which {}",
                        parsed.name, defect
                    ));
                }

                // Parameters carry the same production as the preference itself, and
                // the optional bracket around `parameter` is why a bare `;` is not a
                // defect: `foo; ; bar` writes two empty repetitions of the group and
                // derives from the grammar as written.
                //
                // cite(RFC 7240 § 2): "parameter  = token [ BWS "=" BWS word ]"
                // cite(RFC 7240 § 2): "An optional set of parameters can be specified for any preference token."
                for segment in segments {
                    let param = trim_ows(segment);
                    if param.is_empty() {
                        continue;
                    }
                    let parsed_param = match parse_token_bws_word(param) {
                        Ok(parsed_param) => parsed_param,
                        Err(e) => {
                            return violation(format!(
                                "Prefer parameter '{}' in member '{}' does not match parameter: {}",
                                shown_in_finding(param),
                                shown_in_finding(member),
                                e
                            ))
                        }
                    };
                    // The same pair of sentences at the same construct: the trim is
                    // the recipient's requirement and the finding is the sender's.
                    //
                    // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
                    // cite(RFC 9110 § 5.6.3): "A recipient MUST parse for such bad whitespace and remove it before interpreting the protocol element."
                    if parsed_param.bws {
                        return violation(format!(
                            "Prefer parameter '{}' in member '{}' has whitespace around its '='; the grammar admits BWS there only for historical reasons",
                            shown_in_finding(param),
                            shown_in_finding(member)
                        ));
                    }
                }

                // Writing a preference twice costs the second one, and the document
                // states the consequence rather than leaving it to the server: the
                // first instance is the one that counts. The two preferences whose
                // sections call them mutually exclusive are this case — `return`
                // written twice is one name twice — and there the cost is both.
                //
                // cite(RFC 7240 § 2): "To avoid any possible ambiguity, individual preference tokens SHOULD NOT appear multiple times within a single request."
                // cite(RFC 7240 § 2): "If any preference is specified more than once, only the first instance is to be considered."
                // cite(RFC 7240 § 4.2): "The "return=minimal" and "return=representation" preferences are mutually exclusive directives."
                // cite(RFC 7240 § 4.4): "The "handling=strict" and "handling=lenient" preferences are mutually exclusive directives."
                if seen.contains(&name) {
                    return violation(format!(
                        "Prefer names the '{}' preference more than once; only the first instance is considered",
                        parsed.name
                    ));
                }
                seen.push(name);
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Prefer header syntax")
    }

    fn description(&self) -> &'static str {
        "Reads a request's `Prefer` field against RFC 7240 §2's grammar — `Prefer = 1#preference`, `preference = token [ BWS \"=\" BWS word ] *( OWS \";\" [ OWS parameter ] )`, `parameter = token [ BWS \"=\" BWS word ]` — and against the productions §4 writes for the four preferences it defines.\n\n**The field is read as one list of octets.** A client MAY spread its preferences over several `Prefer` field lines, and §2 says that is equivalent to one field carrying their comma-separated concatenation, so the lines are joined before the members are counted and a member written at a line boundary is one member. The value is not decoded: a `word` may be a `quoted-string`, `qdtext` admits `obs-text`, and refusing the field over an octet above %x7E would hide the legal value and the illegal one alike. Commas and semicolons inside a `quoted-string` are `qdtext` and not separators.\n\n**`1#preference` requires one non-empty member.** `Prefer:`, `Prefer: ,` and `Prefer: ,   ,` are three spellings of the same defect, and an empty element beside a real one is §5.6.1.1's separate sender MUST NOT. A bare `;` is *not* one: §2 writes the parameter inside an optional bracket, so `foo; ; bar` derives from the grammar as written.\n\n**A value is a `word`, and `word` is `token / quoted-string`.** Neither derives the empty string, so `foo=` matches nothing — the spelling for a preference with no value is `foo`, or `foo=\"\"`, which §2 says means the same thing. The quoting is not part of the value: `return=\"minimal\"` and `return=minimal` are the same preference.\n\n**The four preferences RFC 7240 defines are checked against their own productions.** `respond-async` is the token alone and admits no value; `return` admits `representation` or `minimal`; `handling` admits `strict` or `lenient`; `wait` admits a `delta-seconds`, which is `1*DIGIT` and so has no sign and no decimal point. RFC 7240 states no requirement about any of these values — it writes the grammar and stops — so what makes a value outside them a finding is RFC 9110 §2.2's MUST NOT on generating elements that do not match the corresponding ABNF. The comparison folds case because an ABNF string literal matches any case (RFC 5234 §2.3); §2's rule that *values* are case sensitive decides whether two values written in two messages are the same value, which is `preference_applied_header_valid`'s question and not this one's.\n\n**Any other preference name is left alone.** The \"HTTP Preferences\" registry is open, and §5.1's template puts a registered preference's admitted values in its own registration — so the value of a preference defined elsewhere is not readable from RFC 7240, and §2 requires a server that cannot place a token to ignore it rather than signal an error. Parameters are not judged beyond their grammar for the same reason: §2 makes their meaning depend on the preference's own definition.\n\n**A repeated preference token is reported.** §2 asks clients not to write one twice and says the first instance is the one considered, so the second is text no recipient acts on; §4.2 and §4.4 add that `return` and `handling` written twice can cost the client both instances.\n\n**Not decided here:** whether the server honored anything — `preference_applied_header_valid` compares this field against the response's `Preference-Applied`. Nor §2's `Vary` MUST: its antecedent is a fact about the *server*, so the message that can state it is the response rather than this one. `prefer_header_and_preference_applied` reads a `Preference-Applied` as the server saying it applies that preference and asks for the `Vary` there."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_7240_2,
            RFC_7240_4,
            RFC_7240_5_1,
            RFC_7240_1_1,
            RFC_9110_2_2,
            RFC_9110_5_6_1,
            RFC_9110_5_6_3,
            RFC_9111_1_2_2,
            RFC_5234_2_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(RFC 7240 §2's own example of three preferences over two field lines)"),
                snippet: "POST /foo HTTP/1.1\nHost: example.org\nPrefer: respond-async, wait=100\nPrefer: handling=lenient\nDate: Tue, 20 Dec 2011 12:34:56 GMT",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a parameter, and a quoted-string carrying the grammar's own delimiters)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: return=representation; foo=\"a,b;c\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(`foo`, `foo=\"\"` and a bare `;` all derive from the grammar)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: respond-async; bar=\"\"; ; baz",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`word` is `token / quoted-string`; neither derives the empty string)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: return=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`return` admits only \"representation\" or \"minimal\")"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: return=whatever",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`wait` takes a delta-seconds, which has no sign)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: wait=-1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`respond-async` is the token alone and defines no value)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: respond-async=1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(only the first instance of a preference is considered)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: return=minimal, return=representation",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(BWS around the '=' is admitted by the grammar and forbidden to senders)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: return = minimal",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(1#preference requires one non-empty member)"),
                snippet: "POST /items HTTP/1.1\nHost: example.org\nPrefer: ,",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PreferHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Build a request from raw `Prefer` field lines, so a test can write more
    /// than one and can write octets no `&str` API would carry.
    fn tx_with(prefer: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        for line in prefer {
            hm.append(
                "prefer",
                hyper::header::HeaderValue::from_bytes(line).expect("field line"),
            );
        }
        tx.request.headers = hm;
        tx
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = PreferHeaderValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    fn check_value(value: &str) -> Option<Violation> {
        check(&tx_with(&[value.as_bytes()]))
    }

    #[rstest]
    // The preferences RFC 7240 § 4 defines, written as its own examples write them.
    #[case("respond-async", false)]
    #[case("return=representation", false)]
    #[case("return=minimal", false)]
    #[case("handling=lenient", false)]
    #[case("handling=strict", false)]
    #[case("wait=100", false)]
    #[case("wait=0", false)]
    #[case("respond-async, wait=10", false)]
    // An ABNF string literal matches any case.
    #[case("return=Minimal", false)]
    #[case("RETURN=minimal", false)]
    // The quoting is not part of the value.
    #[case("return=\"minimal\"", false)]
    // Each of the four measured against its own production.
    #[case("return=whatever", true)]
    #[case("return", true)]
    #[case("return=\"\"", true)]
    #[case("handling=whatever", true)]
    #[case("handling", true)]
    #[case("wait=abc", true)]
    #[case("wait=-1", true)]
    #[case("wait=1.5", true)]
    #[case("wait", true)]
    #[case("respond-async=1", true)]
    #[case("respond-async=\"\"", false)]
    // A name this document does not define keeps its value unjudged.
    #[case("priority=5", false)]
    #[case("depth-noroot", false)]
    #[case("my-extension=anything-at-all", false)]
    // `preference` and `parameter` share one production.
    #[case("=abc", true)]
    #[case("\"quoted\"", true)]
    #[case("f@o=1", true)]
    #[case("foo=bad@", true)]
    #[case("foo=\"bad", true)]
    #[case("respond-async; =foo", true)]
    #[case("respond-async; n@me=1", true)]
    #[case("respond-async; foo", false)]
    #[case("respond-async; foo=\"a\\\"b\"", false)]
    // `word` derives no empty string, in either position.
    #[case("foo=", true)]
    #[case("respond-async; foo=", true)]
    // `foo=""` is the spelling for "no value", and it is not a defect.
    #[case("foo=\"\"", false)]
    #[case("respond-async; bar=\"\"", false)]
    // The parameter sits inside an optional bracket, so a bare `;` derives.
    #[case("respond-async; ; wait=100", false)]
    #[case("respond-async; ;", false)]
    // `OWS` around the `;` is in the production; `BWS` around the `=` is the finding.
    #[case("respond-async ; foo", false)]
    #[case("respond-async; foo = bar", true)]
    #[case("foo = bar", true)]
    #[case("foo= bar", true)]
    // The quoted-string may carry the delimiters of the grammar around it.
    #[case("foo=\"a,b\"", false)]
    #[case("foo=\"a;b\"", false)]
    #[case("foo=\"a=b\"", false)]
    // `1#preference` and its empty elements.
    #[case("", true)]
    #[case(",", true)]
    #[case(",   ,", true)]
    #[case("respond-async,", true)]
    #[case("respond-async,,wait=100", true)]
    // A repeated preference token costs the second instance.
    #[case("return=minimal, return=representation", true)]
    #[case("respond-async, RESPOND-ASYNC", true)]
    #[case("respond-async, wait=100, handling=strict", false)]
    fn check_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_value(value);
        assert_eq!(
            v.is_some(),
            expect_violation,
            "Prefer: {:?} gave {:?}",
            value,
            v
        );
    }

    #[test]
    fn scope_is_client() {
        let rule = PreferHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    /// `qdtext` admits `obs-text`, so this member is conforming and cannot be
    /// judged through a UTF-8 decode. The rule used to answer it with a
    /// "non-UTF8 value" finding about the whole field.
    #[test]
    fn obs_text_inside_a_quoted_string_is_not_a_finding() {
        assert!(check(&tx_with(&[b"foo=\"caf\xE9\""])).is_none());
    }

    /// The same octet outside the quoted-string is a `token` character no
    /// `tchar` admits, and it is named as the octet it is.
    #[test]
    fn obs_text_outside_a_quoted_string_is_reported_as_the_octet() {
        let v = check(&tx_with(&[b"caf\xE9"])).expect("finding");
        assert!(v.message.contains("0xE9"), "{}", v.message);
    }

    /// § 2 makes several field lines one value, so a member written across the
    /// boundary is one member — and the comma the join inserts is the one the
    /// list grammar prints.
    #[test]
    fn a_member_split_across_field_lines_is_one_member() {
        assert!(check(&tx_with(&[b"foo=\"a", b"b\""])).is_none());
    }

    /// The RFC's own two-line example, which has to survive the join.
    #[test]
    fn the_documents_own_multi_line_example_is_clean() {
        assert!(check(&tx_with(&[b"respond-async, wait=100", b"handling=lenient"])).is_none());
    }

    /// The join is also what makes an empty field line an empty list element.
    #[test]
    fn an_empty_field_line_beside_a_member_is_an_empty_list_element() {
        let v = check(&tx_with(&[b"", b"respond-async"])).expect("finding");
        assert!(v.message.contains("empty list element"), "{}", v.message);
    }

    /// A value read as octets can carry HTAB inside a `quoted-string`, which
    /// would break the line of a finding rather than appear in it.
    #[test]
    fn a_value_reaching_a_finding_is_escaped_into_it() {
        let v = check(&tx_with(&[b"return=\"a\tb\""])).expect("finding");
        assert!(
            v.message.contains("a\\tb") && !v.message.contains('\t'),
            "{}",
            v.message
        );
    }

    /// The finding for a preference outside its own production has to name the
    /// preference and the value, since the member alone does not say which of
    /// the two the reader should look at.
    #[test]
    fn a_value_outside_its_production_names_both() {
        let v = check_value("return=whatever").expect("finding");
        assert!(
            v.message.contains("return") && v.message.contains("whatever"),
            "{}",
            v.message
        );
    }

    /// § 2's `Vary` requirement and the honoring comparison belong to other
    /// rules; run the one that owns the request/response pair rather than
    /// describing it.
    #[test]
    fn whether_a_preference_was_honored_belongs_to_the_neighbouring_rule() {
        let neighbour = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "preference_applied_header_valid")
            .expect("preference_applied_header_valid is registered");
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("prefer", "return=minimal")]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "preference-applied",
            "respond-async",
        )]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "prefer_header_valid",
            "preference_applied_header_valid",
        ]);
        let hist = crate::transaction_history::TransactionHistory::empty();
        assert!(
            check(&tx).is_none(),
            "the request's own syntax is clean, so this rule says nothing"
        );
        assert!(
            crate::test_helpers::run_rule(*neighbour, &tx, &hist, &cfg).is_some(),
            "the neighbour is the rule that compares the two fields"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = PreferHeaderValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("prefer_header_valid".into(), toml::Value::Table(table));

        rule.prepare(&cfg)?;
        Ok(())
    }
}
