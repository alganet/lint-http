// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{
    LIST_MEMBER_EMPTY, LIST_MEMBER_MISSING, RFC_9110_5_6_1_1, RFC_9110_5_6_1_2,
};
use crate::violations::origin::{
    origin_defect, ORIGIN_MALFORMED, ORIGIN_PATH_FORBIDDEN, RFC_6454_7_1,
};
use crate::violations::uri::{
    RFC_3986_2, RFC_3986_3_1, URI_CHARACTER_FORBIDDEN, URI_SCHEME_CHARACTER_FORBIDDEN,
    URI_SCHEME_EMPTY, URI_SCHEME_LEADING_LETTER_MISSING,
};
use crate::violations::ViolationDef;

pub struct TimingAllowOriginValid;

/// The list construct's two defects, which is what this field borrows.
///
/// `Timing-Allow-Origin = 1#( origin-or-null / wildcard )` is written with
/// RFC 9110's List Extension and the document says so where it prints the ABNF,
/// so both halves of the construct answer here exactly as they answer for an
/// `Accept-Patch` or a `Warning`: the floor the `1#` puts under the value, and
/// the empty element a sender must not generate. A W3C document borrowing the
/// construct borrows its defects with it.
///
/// **A member is a serialized origin, and that is not this rule's either.** The
/// two literals the grammar admits beside it — the case-sensitive `null` and
/// the wildcard — are members no reading can fail, so what is left to measure
/// is the production the `Origin` field is written in, read here by the same
/// typed reader those rules call. The bool predicate this replaced could only
/// say *no*: a member with a path, a member whose scheme is not a scheme name
/// and a member holding an octet no URI is composed from all arrived as one
/// verdict, where the reader names each of them.
///
/// So the entries below the list's two are the ones `origin_matching_for_cors`
/// reports, and this is the third rule to read an origin. **The reference to
/// RFC 6454 § 7.1 comes with them**: that section is where a serialized origin
/// is defined, and a finding saying a member is not one cites the sentence that
/// says what one is — the historical shape Fetch supplants and this reader
/// still implements.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_MISSING,
    &LIST_MEMBER_EMPTY,
    &ORIGIN_MALFORMED,
    &ORIGIN_PATH_FORBIDDEN,
    &URI_SCHEME_EMPTY,
    &URI_SCHEME_LEADING_LETTER_MISSING,
    &URI_SCHEME_CHARACTER_FORBIDDEN,
    &URI_CHARACTER_FORBIDDEN,
];
/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RESOURCE_TIMING_3_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Resource Timing",
    section: Some("3.5.2"),
    url: "https://www.w3.org/TR/resource-timing/#sec-timing-allow-origin",
    note: "`Timing-Allow-Origin` response header and its ABNF",
};
const FETCH_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.2"),
    url: "https://fetch.spec.whatwg.org/#origin-header",
    note: "`origin-or-null` and `serialized-origin`, the productions the grammar's members resolve to (`null` is case-sensitive)",
};

impl RuleMeta for TimingAllowOriginValid {
    fn id(&self) -> &'static str {
        "timing_allow_origin_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Timing-Allow-Origin Header Validity")
    }

    fn description(&self) -> &'static str {
        "Validate the `Timing-Allow-Origin` response header values. The header's value\nmust be `*` (wildcard), the lowercase literal `null` (the grammar's `%s\"null\"`\nis case-sensitive), or one or more serialized origins (`scheme://host[:port]`).\nMultiple header fields are allowed and their values are combined using HTTP\nlist semantics, so the rule reads the combined value as one list. It reports a\nvalue naming no member at all (an empty value, or nothing but commas), an\nempty list element anywhere in it (a leading, doubled or trailing comma, or an\nempty line beside a full one), and every member that is not a serialized\norigin."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RESOURCE_TIMING_3_5_2,
            FETCH_3_2,
            RFC_6454_7_1,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_3986_3_1,
            RFC_3986_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https://example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https://a, https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https:///foo",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`null` is case-sensitive"),
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: NULL",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: \t",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A trailing comma is an empty member"),
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https://a.example, ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A lone comma names no origin"),
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: ,",
            },
        ]
    }
}

impl Rule for TimingAllowOriginValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per member. `1#( origin-or-null / wildcard )` names one
        // origin per position -- each a document origin the timing attributes
        // are being exposed to -- so a value naming three that derive from no
        // origin is three names the operator has to correct, and a walk that
        // returned at the first named one.
        let findings = || -> Vec<Violation> {
            // The header is server-sent: it rides responses, so only the response side is
            // inspected.
            // cite(Resource Timing § 3.5.2): "Server-side applications may return the Timing-Allow-Origin HTTP response header to allow the User Agent to fully expose, to the document origin(s) specified, the values of attributes that would have been zero due to those cross-origin restrictions."
            let Some(resp) = tx.response.as_ref() else {
                return Vec::new();
            };

            // One list however many lines carry it, and the resource-timing
            // document says so in its own words: a second line is further members
            // of the same value. So an empty `Timing-Allow-Origin:` line beside a
            // line naming an origin is an empty *member* of that value, not a
            // second field naming nothing.
            //
            // Read as the octets the sender wrote: every member derives from `*`,
            // the case-sensitive `null` or a serialized origin, and all three are
            // inside visible US-ASCII -- so an octet above it is a member deriving
            // from none of them, which the origin finding below already says.
            // cite(Resource Timing § 3.5.2): "The sender MAY generate multiple Timing-Allow-Origin header fields."
            // cite(Resource Timing § 3.5.2): "The recipient MAY combine multiple Timing-Allow-Origin header fields by appending each subsequent field value to the combined field value in order, separated by a comma."
            let Some(value) = crate::helpers::headers::combined_field_value_as_written(
                &resp.headers,
                "timing-allow-origin",
            ) else {
                return Vec::new();
            };

            let mut out = Vec::new();
            let mut saw_an_empty_member = false;
            let mut members_present = 0usize;

            // The sender's walk, which keeps the empty member. The field is
            // written with RFC 9110's list construct, so its sender requirement
            // is § 5.6.1.1's: every position holds an element, the last one
            // included. A trailing comma used to be excused here on § 5.6.1.2's
            // sentence, which has a *recipient* parse and ignore one -- the other
            // party's requirement, and the one that erases the evidence for this
            // one. No member admits a `quoted-string`, so the naive cut at every
            // comma is the right one.
            // cite(Resource Timing § 3.5.2): "The header’s value is represented by the following ABNF [RFC5234] (using List Extension, [RFC9110]):"
            // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
            // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
            for m in crate::helpers::list::sender_list_members(&value) {
                if m.is_empty() {
                    saw_an_empty_member = true;
                    continue;
                }
                members_present += 1;

                // `wildcard` and the case-sensitive lowercase `null` are the two
                // non-origin members the grammar admits (both productions resolve
                // into Fetch).
                // cite(Fetch § 3.2): "origin-or-null = serialized-origin / %s"null" ; case-sensitive"
                if m == "*" || m == "null" {
                    continue;
                }

                // Anything else must be a serialized origin, and the typed
                // reader is what says which way it is not one — the same
                // reader `origin_matching_for_cors` calls, so a path after
                // the authority draws the same id here as it does there.
                if let Err(defect) = crate::helpers::origin::validate_origin_value(m) {
                    out.push(ctx.report_with(
                        origin_defect(defect),
                        format!(
                            "Timing-Allow-Origin contains invalid origin: '{}' ({})",
                            crate::helpers::shown::shown_in_finding(m),
                            defect.message()
                        ),
                    ));
                }
            }

            // The `1#` floor, over the combined value. § 5.6.1.2 prints the
            // values it rejects, and they are exactly the ones whose every
            // position was empty: the empty field value, a lone comma, and
            // commas with only whitespace between them.
            // cite(Resource Timing): "Timing-Allow-Origin = 1#( origin-or-null / wildcard )"
            // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
            if members_present == 0 {
                out.push(ctx.report_with(
                    &LIST_MEMBER_MISSING,
                    format!(
                        "Timing-Allow-Origin is `1#( origin-or-null / wildcard )` and names no origin; the response's field lines combine to '{}'",
                        crate::helpers::shown::shown_in_finding(&value)
                    ),
                ));
            }
            // Only beside a member that *is* there: a value holding nothing else
            // has not written a member badly, it has written none, which is the
            // floor above saying the same defect once. One finding however many
            // gaps the value holds -- what § 5.6.1.1 forbids generating is an
            // empty *element*, and a value written with three of them is one list
            // with gaps in it. The value is quoted as the combined one and the
            // message says so, because where the gap is an empty line beside a
            // full one the comma is the join's, and an operator grepping a
            // capture for the quoted text would otherwise find nothing.
            else if saw_an_empty_member {
                out.push(ctx.report_with(
                    &LIST_MEMBER_EMPTY,
                    format!(
                        "Timing-Allow-Origin holds an empty list element; the response's field lines combine to '{}'. Every position in `1#( origin-or-null / wildcard )` names an origin, the wildcard or `null`, and a comma with nothing beside it names none",
                        crate::helpers::shown::shown_in_finding(&value)
                    ),
                ));
            }

            out
        };
        findings()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &TimingAllowOriginValid;

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every origin the response named is answered.** `1#( origin-or-null /
    /// wildcard )` names one document origin per position, so a value naming two
    /// that derive from no origin is two names to correct — and the gap beside
    /// them is the list's own defect, counted once.
    #[test]
    fn every_defective_origin_is_reported_beside_the_gap() {
        let rule = TimingAllowOriginValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "timing_allow_origin_valid",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "timing-allow-origin",
                "http://a.example/path,,notanorigin,,https://ok.example",
            )],
        );
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<_> = found.iter().map(|v| v.violation.as_str()).collect();
        assert!(ids.contains(&"origin_path_forbidden"), "{ids:?}");
        assert!(ids.contains(&"origin_malformed"), "{ids:?}");
        assert_eq!(
            ids.iter().filter(|i| **i == "list_member_empty").count(),
            1,
            "the gaps are one list defect: {ids:?}"
        );
    }

    /// The two halves of the list construct, answering with the ids every
    /// other `1#` field answers with — out of a rule whose own findings are a
    /// W3C document's and whose members are Fetch's.
    #[test]
    fn the_list_construct_reports_the_ids_it_always_does() {
        for (value, id) in [
            ("  ", "list_member_missing"),
            ("https://a, , https://b", "list_member_empty"),
        ] {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("timing-allow-origin", value)]);
            let found = crate::test_helpers::run_rule(
                &TimingAllowOriginValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "timing_allow_origin_valid",
                ]),
            )
            .expect("a finding");
            assert_eq!(found.violation, id, "{value}");
        }
    }
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[test]
    fn no_response_no_violation() {
        let rule = TimingAllowOriginValid;
        let tx = make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_without_header_returns_none() {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    #[case("*")]
    #[case("null")]
    #[case("https://example.com")]
    #[case("  https://example.com  ")]
    #[case("https://a, https://b")]
    fn valid_values(#[case] val: &str) {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "expected no violation for '{}': got {:?}",
            val,
            v
        );
    }

    /// The octet is a member deriving from none of the three alternatives, and
    /// that is what the finding says. It used to be a verdict about the octet
    /// class, reached before any member had been read — which also meant a
    /// legible origin written beside the octet was never measured.
    #[test]
    fn an_octet_is_a_value_deriving_from_none_of_the_alternatives() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = TimingAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.insert(
            "timing-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert!(v.message.contains("invalid origin"), "{}", v.message);
    }

    /// **The list construct at both of its ends, each with the id it answers
    /// with.** A trailing comma is an empty element the sender generated, and
    /// used to be excused on the recipient's sentence; a value of nothing but
    /// commas is § 5.6.1.2's own spelling of a `1#` list below its floor, and
    /// drew nothing at all. Each finding quotes the value it was read from.
    #[rstest]
    #[case("https://a,  ", "list_member_empty")]
    #[case(", https://a", "list_member_empty")]
    #[case("*,", "list_member_empty")]
    #[case(",", "list_member_missing")]
    #[case(" , , ", "list_member_missing")]
    #[case(" ", "list_member_missing")]
    fn an_empty_position_is_reported_wherever_it_is(#[case] val: &str, #[case] id: &str) {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
        );
        let found = crate::test_helpers::run_rule_all(
            &TimingAllowOriginValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "timing_allow_origin_valid",
            ]),
        );
        assert_eq!(found.len(), 1, "one finding for '{val}': {found:?}");
        assert_eq!(found[0].violation, id, "{val}");
        assert!(
            found[0].message.contains(&format!("'{val}'")),
            "the finding quotes the value: {}",
            found[0].message
        );
    }

    /// Several lines are one value, so an empty line beside an origin is an
    /// empty member of it -- the combined value is `https://a,` -- and not a
    /// field naming nothing, which the floor would have said.
    #[test]
    fn an_empty_line_beside_an_origin_is_an_empty_member() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.append("timing-allow-origin", HeaderValue::from_static(""));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let found = crate::test_helpers::run_rule_all(
            &TimingAllowOriginValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "timing_allow_origin_valid",
            ]),
        );
        let ids: Vec<_> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, ["list_member_empty"], "{found:?}");
        assert!(
            found[0].message.contains("'https://a,'"),
            "{}",
            found[0].message
        );
    }

    #[test]
    fn ipv6_origin_is_valid() {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https://[::1]:8080")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn wildcard_and_origin_mix_is_accepted() {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "*, https://example.com")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // § 3.2 terminates an authority at "/", "?" or "#", and a serialized origin
    // ends where its authority does. Only the first of the three reached this
    // rule until the shared validator stopped enumerating them by hand.
    #[rstest]
    #[case("https://a/")]
    #[case("https://a/path")]
    #[case("https://ok.example, https://b/path")]
    #[case("https://a?x=1")]
    #[case("https://a#frag")]
    #[case("https://ok.example, https://b#frag")]
    // The authority's *contents*, unmeasured until the host was asked its own
    // production rather than asked for a space, a tab and an at-sign.
    #[case("https://exa|mple.com")]
    #[case("https://ok.example, https://a<b>c")]
    #[case("https://a%zzb")]
    #[case("https://[foo]")]
    fn member_with_anything_after_the_authority_is_violation(#[case] val: &str) {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.unwrap_or_else(|| panic!("expected violation for '{}'", val));
        assert!(v.message.contains("invalid origin"));
    }

    /// The reader names which way a member is not a serialized origin, and the
    /// ids are the ones `origin_matching_for_cors` reports for the same
    /// production — which is what the bool predicate could not do: every row
    /// here used to arrive as one verdict.
    #[rstest]
    #[case("https://a/path", "origin_path_forbidden")]
    #[case("1http://a", "uri_scheme_leading_letter_missing")]
    #[case("ht_tp://a", "uri_scheme_character_forbidden")]
    #[case("https://a<b>c", "uri_character_forbidden")]
    #[case("NULL", "origin_malformed")]
    fn the_reader_names_which_way_a_member_is_not_an_origin(#[case] val: &str, #[case] id: &str) {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("expected violation for '{val}'"));
        assert_eq!(v.violation, id, "{val}");
    }

    #[test]
    fn uppercase_null_is_violation() {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "NULL")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn invalid_origin_is_violation() {
        let rule = TimingAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https:///foo")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn multiple_header_fields_are_combined() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = TimingAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.append("timing-allow-origin", HeaderValue::from_static("https://b"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "expected no violation for combined fields: got {:?}",
            v
        );
    }

    #[test]
    fn needs_a_response() {
        let rule = TimingAllowOriginValid;
        assert!(rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = TimingAllowOriginValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "timing_allow_origin_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }
}
