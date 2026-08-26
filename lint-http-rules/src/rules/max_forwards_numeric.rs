// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, describe_octet, trim_ows};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MaxForwardsNumeric;

impl Rule for MaxForwardsNumeric {
    fn id(&self) -> &'static str {
        "max_forwards_numeric"
    }

    /// The field is a request field: it limits how far a request travels, and the
    /// two methods it works with are request methods.
    ///
    /// cite(RFC 9110 § 7.6.2): "The "Max-Forwards" header field provides a mechanism with the TRACE (Section 9.3.8) and OPTIONS (Section 9.3.7) request methods to limit the number of times that the request is forwarded by proxies."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        // No method gate, and the field is read before anything about the request
        // line is. The mechanism is defined for TRACE and OPTIONS, and what the
        // section says about the field on other methods is addressed to the
        // *recipient*, as a MAY: nothing forbids a client from sending it, so its
        // presence on a GET is not reported. Its shape still is — a field value is
        // measured against the field's grammar whatever start-line preceded it.
        //
        // cite(RFC 9110 § 7.6.2): "A recipient MAY ignore a Max-Forwards header field received with any other request methods."
        let headers = &tx.request.headers;

        // The header section only. Whether *any* field may be sent in a trailer
        // section is § 6.5.1's deny-by-default question and
        // `trailer_fields_valid`'s finding; a `Max-Forwards` arriving
        // after the content could not have been read before the message was
        // forwarded anyway, which is the whole of what the field is for.
        //
        // The value is read as the sender wrote it, on two counts. All of the
        // section's lines are one value, so two lines are not two values to be
        // measured apart — the recipient recombines them and gets a comma, which
        // `1*DIGIT` does not generate. And every octet is decoded to the `char` of
        // the same value: `to_str` accepts only visible US-ASCII, so a value
        // carrying %xFF would otherwise become "this message has no `Max-Forwards`
        // field", a claim about the message rather than about the octet that is
        // wrong.
        //
        // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
        let value = combined_field_value_as_written(headers, "max-forwards")?;
        let lines = headers.get_all("max-forwards").iter().count();

        if lines > 1 {
            // `Max-Forwards = 1*DIGIT` has no `#(...)` alternative anywhere in it, so
            // § 5.3's exception does not apply and one message carries at most one
            // field line. The sentence saying so is the shared one, and this is the
            // only one of the five callers with nothing to append to it: a comma is
            // not a `DIGIT`, so the joined value is simply malformed, which the
            // production named in the preamble already tells the reader.
            return violation(crate::helpers::headers::singleton_field_preamble(
                "Max-Forwards",
                lines,
                &value.escape_debug().to_string(),
                "`Max-Forwards = 1*DIGIT` has no comma-separated-list alternative",
            ));
        }

        // Trimming `OWS` and only `OWS`: the value carries one `char` per octet, so
        // U+00A0 in it is the octet %xA0, which is `obs-text` and not whitespace of
        // any kind. `str::trim` would remove it and report a value of no digits for
        // a defect the octet has.
        //
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        let value = trim_ows(&value);

        // The whole production, and the two things it says. `1*DIGIT` requires at
        // least one digit, so a `Max-Forwards:` carrying nothing is a value this
        // production does not generate — the opposite answer from the `#`-list
        // fields next door, where `#element => [ 1#element ]` makes a value of no
        // members a value. One character of the production apart, and the answers
        // are inverted.
        //
        // cite(RFC 9110 § 7.6.2, label: Max-Forwards grammar): "Max-Forwards = 1*DIGIT"
        if value.is_empty() {
            return violation(
                "Max-Forwards is present with no digits; the field is `Max-Forwards = 1*DIGIT`, which requires at least one".to_string(),
            );
        }

        if let Some(ch) = value.chars().find(|c| !c.is_ascii_digit()) {
            // Every `char` here came from one octet and goes back to it unchanged;
            // the finding names the octet that stopped the parse rather than writing
            // it through, since by definition the production did not admit it.
            return violation(format!(
                "Max-Forwards value '{}' holds {}, which is not a DIGIT; the field is `Max-Forwards = 1*DIGIT`",
                value.escape_debug(),
                describe_octet(ch as u8)
            ));
        }

        // Where the rule stops, and it is not an oversight. The value is a decimal
        // integer with no bound on its length, so it is never parsed into one: a
        // number too large for any integer type is still `1*DIGIT`, and a parse
        // failure is not a grammar failure. What the section requires *of* that
        // number is addressed to the intermediary forwarding the message — check and
        // update it, stop at zero, and do not invent the field for a request that
        // arrived without one. Each is a requirement on a message this transaction
        // does not hold: the capture records the request as received on one leg, so
        // the value the next hop was sent, and whether the same party wrote it, are
        // both outside it. No rule can measure them; `description()` says so, because
        // silence here reads as a verdict that any value forwards fine.
        //
        // cite(RFC 9110 § 7.6.2): "The Max-Forwards value is a decimal integer indicating the remaining number of times this request message can be forwarded."
        // cite(RFC 9110 § 7.6.2): "Each intermediary that receives a TRACE or OPTIONS request containing a Max-Forwards header field MUST check and update its value prior to forwarding the request."
        // cite(RFC 9110 § 7.6.2): "If the received value is zero (0), the intermediary MUST NOT forward the request; instead, the intermediary MUST respond as the final recipient."
        // cite(RFC 9110 § 9.3.7): "A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field."
        None
    }

    fn description(&self) -> &'static str {
        "Validates the `Max-Forwards` request header field's value against its own production, `Max-Forwards = 1*DIGIT` (RFC 9110 §7.6.2): one or more ASCII digits and nothing else. The field limits how many times a `TRACE` or `OPTIONS` request may be forwarded, so a value a proxy cannot read is a limit that does not apply.\n\nAt least one digit is required. `Max-Forwards:` carrying nothing is reported — the opposite answer from the comma-separated-list fields, where a value of no members is a value the production generates; `1*DIGIT` names no such alternative.\n\nThe field is a **singleton**: its grammar has no comma-separated-list form, so a message carries at most one `Max-Forwards` field line (RFC 9110 §5.3), and two lines are reported as that. §5.2 makes them one value in any case, and the comma a recipient recombines them with is not a digit.\n\nA value carrying an octet outside US-ASCII is measured rather than skipped, and the finding names the octet. This is not a UTF-8 question: `1*DIGIT` admits %x30–39 and nothing else, so `obs-text` is reported for not being a digit, which is what is wrong with it. Leading and trailing whitespace is excluded before the value is evaluated (§5.5), and only `SP`/`HTAB` count as that — %xA0 is an octet, not whitespace.\n\nThe value is never parsed into an integer. `1*DIGIT` puts no bound on its length, so `Max-Forwards: 0000000000000000000000005` is a conforming value that no integer type holds, and leading zeros are likewise fine.\n\n**Scope: this rule reads the field's syntax and nothing else.** §7.6.2's requirements on the *value* are addressed to the intermediary forwarding the message — it MUST check and update the value before forwarding, MUST NOT forward at all when it receives zero (it responds as the final recipient instead), and §9.3.7 says a proxy MUST NOT generate the field while forwarding a request that arrived without it. A captured transaction records the request as it was received on one leg; the message that was forwarded upstream is not in it, so nothing here can tell whether the value was decremented, honoured at zero, or written by the sender at all. Those are gaps in what any rule can measure, not checks this rule leaves out.\n\nThe field on a method other than `TRACE` or `OPTIONS` is not reported. §7.6.2 says a recipient MAY ignore it there — a permission granted to the recipient, not a prohibition on the sender — so such a request has a syntactically valid field that limits nothing. Whether the field may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s finding."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2",
                note: "The field: its grammar (`1*DIGIT`), the methods it works with, and the recipient's permission to ignore it on the others. The section's requirements on intermediaries — check and update the value, do not forward at zero — are stated here and are not measurable from one captured leg; this rule reads the syntax only",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "A sender MUST NOT generate multiple field lines with the same name unless the field's definition allows them to be recombined as a comma-separated list. `Max-Forwards` has no such alternative, so two lines are reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
                note: "Repeated field lines in one section are one field value, joined with a comma — so the value measured against `1*DIGIT` is the one a recipient reads",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "Singleton fields, why detecting a singleton sent with several members is worth doing, and the MUST to exclude leading and trailing whitespace before evaluating a field value",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7",
                note: "A client MAY send the field in an OPTIONS request to target a specific recipient, and a proxy MUST NOT generate it while forwarding a request that arrived without it — the second is undecidable from a captured message, since nothing on the wire records who wrote a field",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Zero: the request stops at the first recipient, which answers it"),
                snippet: "TRACE / HTTP/1.1\nHost: example.com\nMax-Forwards: 0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("`1*DIGIT` says nothing about leading zeros or magnitude"),
                snippet: "OPTIONS * HTTP/1.1\nHost: example.com\nMax-Forwards: 007",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`-` is not a DIGIT; the production has no sign"),
                snippet: "TRACE / HTTP/1.1\nHost: example.com\nMax-Forwards: -1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A decimal integer, not a decimal fraction"),
                snippet: "OPTIONS * HTTP/1.1\nHost: example.com\nMax-Forwards: 1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A singleton sent with two members, on one line: `,` is not a DIGIT"),
                snippet: "TRACE / HTTP/1.1\nHost: example.com\nMax-Forwards: 120, 240",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`1*DIGIT` requires a digit, so a value of none is not a value"),
                snippet: "TRACE / HTTP/1.1\nHost: example.com\nMax-Forwards:",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MaxForwardsNumeric;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// Every fixture in this module is built here, from raw octets.
    ///
    /// Two reasons for the one constructor. The field's lines are one value, so a
    /// fixture that can only write one line cannot state the case where the second
    /// line is the finding. And the octets go in as octets: `HeaderValue::from_str`
    /// refuses the `obs-text` this rule used to answer with a claim about UTF-8.
    fn max_forwards(lines: &[&[u8]]) -> Option<Violation> {
        let rule = MaxForwardsNumeric;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        for line in lines {
            hm.append(
                "max-forwards",
                HeaderValue::from_bytes(line).expect("field value"),
            );
        }
        tx.request.headers = hm;
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case(b"0")]
    #[case(b"1")]
    #[case(b"10")]
    #[case(b"01")]
    #[case(b"007")]
    #[case(b"255")]
    #[case(b"0000000000000000000000005")]
    fn a_value_of_digits_is_a_value(#[case] value: &[u8]) {
        let v = max_forwards(&[value]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// § 5.5's MUST on the parser, and only `SP`/`HTAB` are what it excludes.
    #[rstest]
    #[case(b" 5")]
    #[case(b"5 ")]
    #[case(b"\t5\t")]
    fn surrounding_ows_is_excluded_before_the_value_is_evaluated(#[case] value: &[u8]) {
        let v = max_forwards(&[value]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// `1*DIGIT`, not `*DIGIT`. The inverse of the `#`-list fields, where a value of
    /// no members is a value the production generates.
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t")]
    fn a_value_of_no_digits_is_not_a_value(#[case] value: &[u8]) {
        let v = max_forwards(&[value]).expect("violation");
        assert!(v.message.contains("no digits"), "{}", v.message);
    }

    #[rstest]
    #[case(b"-1", "'-'")]
    #[case(b"1.0", "'.'")]
    #[case(b"abc", "'a'")]
    #[case(b"120, 240", "','")]
    #[case(b"+5", "'+'")]
    #[case(b"5s", "'s'")]
    fn an_octet_that_is_not_a_digit_is_reported_as_the_octet_that_stopped_it(
        #[case] value: &[u8],
        #[case] expected: &str,
    ) {
        let v = max_forwards(&[value]).expect("violation");
        assert!(v.message.contains("not a DIGIT"), "{}", v.message);
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// `to_str` accepts only visible US-ASCII, so the rule used to answer every one
    /// of these with "Max-Forwards header contains non-UTF8 value" — a claim about an
    /// encoding, made of a value whose defect is that `1*DIGIT` admits %x30-39 alone.
    /// %xA0 is the second half of it: `str::trim` removes it as whitespace, which
    /// would report a value of no digits for a defect the octet has.
    #[rstest]
    #[case(b"\xff", "0xFF")]
    #[case(b"5\xff", "0xFF")]
    #[case(b"\xa0", "0xA0")]
    #[case(b"5\xc3\xa9", "0xC3")]
    fn an_octet_outside_us_ascii_reaches_the_production_that_excludes_it(
        #[case] value: &[u8],
        #[case] expected: &str,
    ) {
        let v = max_forwards(&[value]).expect("violation");
        assert!(v.message.contains("not a DIGIT"), "{}", v.message);
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// The case that exists only after the lines are counted: each line is a
    /// conforming value on its own, and the message carries a field it must not
    /// carry twice. The rule measured the lines apart and reported neither.
    #[rstest]
    #[case(&[b"120" as &[u8], b"240"], "2", "120,240")]
    #[case(&[b"5" as &[u8], b"5"], "2", "5,5")]
    #[case(&[b"1" as &[u8], b"2", b"3"], "3", "1,2,3")]
    fn a_singleton_field_written_on_several_lines_is_reported(
        #[case] lines: &[&[u8]],
        #[case] count: &str,
        #[case] joined: &str,
    ) {
        let v = max_forwards(lines).expect("violation");
        // This is the only one of the five callers of the shared preamble with
        // nothing to append, so the pin is the preamble exactly -- which is also
        // what makes it the case that would notice the shared sentence changing
        // under the other four.
        assert_eq!(
            v.message,
            format!(
                "Max-Forwards is written on {count} header lines, which recombine into the one \
                 value '{joined}'; the field is a singleton — `Max-Forwards = 1*DIGIT` has no \
                 comma-separated-list alternative — so a sender must not generate more than one \
                 field line for it (RFC 9110 §5.3)"
            )
        );
    }

    #[test]
    fn a_request_with_no_max_forwards_field_is_not_measured() {
        let v = max_forwards(&[]);
        assert!(v.is_none(), "{v:?}");
    }

    /// The field is measured whatever the method: § 7.6.2's sentence about other
    /// methods is a permission granted to the recipient, so the field's presence on a
    /// GET is not a finding and its shape still is.
    #[rstest]
    #[case("GET", b"5" as &[u8], false)]
    #[case("GET", b"abc", true)]
    #[case("POST", b"0", false)]
    fn the_method_decides_nothing(
        #[case] method: &str,
        #[case] value: &[u8],
        #[case] expect_violation: bool,
    ) {
        let rule = MaxForwardsNumeric;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "max-forwards",
            HeaderValue::from_bytes(value).expect("field value"),
        );
        tx.request.headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(v.is_some(), expect_violation, "{method} {value:?} -> {v:?}");
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MaxForwardsNumeric;

        for ex in rule.examples() {
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if i == 0 {
                    assert!(
                        line.ends_with(" HTTP/1.1") && !line.contains(':'),
                        "the first line of an example is its request line: {line:?}"
                    );
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }
            assert!(
                pairs
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("max-forwards")),
                "example carries no Max-Forwards field: {}",
                ex.snippet
            );

            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            );
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn scope_is_client() {
        use crate::rules::Rule as _;
        assert_eq!(MaxForwardsNumeric.scope(), crate::rules::RuleScope::Client);
    }
}
