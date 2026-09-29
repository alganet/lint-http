// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::deprecation::{DEPRECATION_MALFORMED, RFC_9745_2_1};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::structured_fields::{
    structured_field_defect, RFC_9651_4_2_2, RFC_9651_4_2_3_1, RFC_9651_4_2_3_3,
    STRUCTURED_FIELD_KEY_MALFORMED, STRUCTURED_FIELD_MEMBER_EMPTY,
    STRUCTURED_FIELD_VALUE_MALFORMED,
};
use crate::violations::ViolationDef;

/// § 5.3's repeated field line, which this rule reports for its own field.
/// The sentence is the catalogue's; what stays here is the reading that says
/// this field's definition has no comma-separated-list alternative.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &DEPRECATION_MALFORMED,
    &STRUCTURED_FIELD_MEMBER_EMPTY,
    &STRUCTURED_FIELD_KEY_MALFORMED,
    &STRUCTURED_FIELD_VALUE_MALFORMED,
];

pub struct DeprecationHeaderSyntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9651_3_3_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("3.3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7",
    note: "Structured Field `Date` item syntax (leading `@`)",
};

impl RuleMeta for DeprecationHeaderSyntax {
    fn id(&self) -> &'static str {
        "deprecation_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "The `Deprecation` response header signals that a resource is deprecated. RFC 9745 defines the header as a Structured Field `Date` item (a numeric timestamp expressed as `@<seconds>`). This rule validates the canonical structured form and flags legacy or invalid forms (literal `true`, HTTP-date, non-numeric `@` values) with helpful messages."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9745_2_1,
            RFC_9651_3_3_7,
            RFC_9110_5_3,
            RFC_9651_4_2_2,
            RFC_9651_4_2_3_3,
            RFC_9651_4_2_3_1,
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
                snippet: "Deprecation: @1688169599\nDeprecation:   @0\nDeprecation: @-1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Deprecation: true\nDeprecation: Wed, 11 Nov 2015 07:28:00 GMT\nDeprecation: @\nDeprecation: @1688169599000000\nDeprecation: @abc",
            },
        ]
    }
}

impl Rule for DeprecationHeaderSyntax {
    fn needs_response(&self) -> bool {
        true
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
            // Deprecation is a response header field, which is why this rule is Server-scoped.
            // cite(RFC 9745 § 2): "The Deprecation HTTP response header field allows a server to communicate to a client application that the resource in the context of the message will be or has been deprecated."
            let resp = tx.response.as_ref()?;

            let mut vals = Vec::new();
            for hv in resp.headers.get_all("deprecation").iter() {
                vals.push(hv);
            }

            // Deprecation is an Item, not a List, so it is not a field whose lines may be
            // recombined as a comma-separated list — the §5.3 exception does not apply and a
            // sender must emit at most one Deprecation field line. RFC 9745 states no
            // "more than one" rule of its own; the prohibition follows from Item + §5.3.
            // cite(RFC 9745 § 2.1): "Deprecation is an Item Structured Header Field; its value MUST be a Date as per Section 3.3.7 of [RFC9651]."
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if vals.len() > 1 {
                return Some(ctx.report_with(&FIELD_LINE_DUPLICATED, "Multiple Deprecation header fields present; Deprecation is a single Structured Field Item (RFC 9745 §2.1), so a response carries at most one Deprecation field line (RFC 9110 §5.3)".into()));
            }

            let hv = vals.into_iter().next()?;

            // Read as octets. A Structured Field Date is `@` and digits and a
            // legacy value is an HTTP-date, and every octet either of them
            // prints is visible US-ASCII -- so the string reader's refusal and
            // this rule's own verdict are the same refusal, and only the
            // second one names the form the sender should have written.
            let s = crate::helpers::headers::field_line_as_written(hv);
            // `trim_ows` and not `str::trim`: the comment above says every octet
            // either form prints is visible US-ASCII, and `str::trim` was
            // removing two that are not -- %xA0 and %x85, both `obs-text` -- so
            // a Structured Field Date with one after its last digit was read as
            // the date alone.
            let s = crate::helpers::headers::trim_ows(&s);

            // An Item carries parameters whether or not its field names any,
            // and RFC 9745 names none: the Date is what precedes the first `;`
            // outside a String, and the parameters are judged after it, in the
            // order § 4.2.3 parses them. A value that opens on its `;` has no
            // Date for them to follow, and is judged whole below.
            // cite(RFC 9651 § 2.3): "Fields that erroneously defined as another type (e.g., Integer) are assumed to be Items (i.e., they allow Parameters)."
            let (s, parameters) = match crate::helpers::structured_fields::split_item(s) {
                ("", _) => (s, None),
                item => item,
            };

            // The valid form is a Structured Field Date: "@" and an Integer,
            // which is signed and at most fifteen digits. A private "@ and
            // digits" test stood here and was wrong at both ends: `@-86400`,
            // the day before the epoch and a Date § 3.3.7 admits, was reported
            // malformed, and sixteen digits, which no Integer has, passed.
            // cite(RFC 9745 § 2.1): "Deprecation is an Item Structured Header Field; its value MUST be a Date as per Section 3.3.7 of [RFC9651]."
            // cite(RFC 9651 § 3.3.7): "their serialization in textual HTTP fields is similar to that of Integers, distinguished from them with a leading "@"."
            // cite(RFC 9651 § 3.3.7): "Dates have a data model that is similar to Integers, representing a (possibly negative) delta in seconds from 1970-01-01T00:00:00Z, excluding leap seconds."
            if crate::helpers::structured_fields::is_date(s) {
                // A valid Structured Field Date, and only a parameter that does
                // not derive is left to say anything about.
                return parameters.map(|defect| {
                    ctx.report_with(
                        structured_field_defect(defect.kind),
                        format!(
                            "Deprecation carries a parameter that does not parse: {}",
                            defect.message
                        ),
                    )
                });
            }

            // Every remaining form fails §2.1's "value MUST be a Date"; the specific 'true' and
            // HTTP-date detections below are diagnostics that produce a more helpful message
            // (both are legacy draft-era forms). Recorded as heuristics in the tracker.
            if s.eq_ignore_ascii_case("true") {
                return Some(ctx.report_with(&DEPRECATION_MALFORMED, "Deprecation header uses legacy token 'true'; RFC 9745 defines Deprecation as a structured date '@<epoch>' (prefer '@<seconds>' form)".into()));
            }

            // Accept legacy HTTP-date but report it as deprecated (helpful message)
            if crate::http_date::is_valid_http_date(s) {
                return Some(ctx.report_with(&DEPRECATION_MALFORMED, "Deprecation header uses legacy HTTP-date format; RFC 9745 specifies Deprecation as a structured date '@<seconds>'".into()));
            }

            // Otherwise it's invalid
            // Escaped on the way in: the value is read as octets, so an
            // `obs-text` byte would otherwise be printed into the finding as
            // the character it is a reading of.
            Some(ctx.report_with(&DEPRECATION_MALFORMED, format!("Deprecation value '{}' is invalid: must be a structured Date item (e.g., '@1688169599') per RFC 9745", crate::helpers::shown::shown_in_finding(s))))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DeprecationHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    /// A Structured Field Date is `@` and digits, which is what this rule says
    /// it reads. `str::trim` was removing the two octets — %xA0 and %x85 —
    /// that `char::is_whitespace` admits and `OWS` does not, so a value with
    /// one after its last digit was read as the date alone and found valid.
    #[test]
    fn an_obs_text_octet_after_the_date_is_not_ows_around_the_value() {
        let rule = DeprecationHeaderSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let judge = |bytes: &[u8]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_octet_pairs(&[("deprecation", bytes)]);
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
        };
        let v = judge(b"@1688169599\xa0").expect("%xA0 is obs-text and no SF Date prints one");
        assert_eq!(v.violation, "deprecation_malformed");
        // `OWS` really is outside the value, and still is.
        assert!(judge(b" @1688169599\t").is_none());
    }

    #[rstest]
    #[case(200, &[("deprecation", "@1688169599")], false)]
    #[case(200, &[("deprecation", "@0")], false)]
    // A Date is an Integer: signed (RFC 9651 § 3.3.7's "possibly negative"
    // delta) and fifteen digits at most (§ 4.2.4).
    #[case(200, &[("deprecation", "@-86400")], false)]
    #[case(200, &[("deprecation", "@-1")], false)]
    #[case(200, &[("deprecation", "@000001688169599")], false)]
    #[case(200, &[("deprecation", "@0000001688169599")], true)]
    #[case(200, &[("deprecation", "@-")], true)]
    #[case(200, &[("deprecation", "@+1")], true)]
    // An Item carries parameters RFC 9745 never names (RFC 9651 § 2.3): the Date
    // is read from in front of them, and only one that does not derive is
    // reported; a value that opens on its `;` has no Date at all.
    #[case(200, &[("deprecation", "@1688169599;x=\"a, b;c\"")], false)]
    #[case(200, &[("deprecation", "@1688169599;x=1;y")], false)]
    #[case(200, &[("deprecation", "@1688169599;X=1")], true)]
    #[case(200, &[("deprecation", "@1688169599;")], true)]
    #[case(200, &[("deprecation", ";x=1")], true)]
    #[case(200, &[("deprecation", "true;x=1")], true)]
    #[case(200, &[("deprecation", "true")], true)]
    #[case(200, &[("deprecation", "Sun, 11 Nov 2018 23:59:59 GMT")], true)]
    #[case(200, &[("deprecation", "bad")], true)]
    fn check_cases(
        #[case] status: u16,
        #[case] hdrs: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, hdrs);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(v.is_some(), "expected violation for headers: {:?}", hdrs);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for headers: {:?}",
                hdrs
            );
        }
        Ok(())
    }

    #[test]
    fn multiple_headers_are_rejected() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.append("deprecation", HeaderValue::from_static("@1688169599"));
        hm.append("deprecation", HeaderValue::from_static("@1688169598"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

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
        assert!(v.is_some());
        Ok(())
    }

    /// The octet is not a claim about the field's encoding: every octet
    /// either the Structured Field Date or the legacy HTTP-date prints is
    /// visible US-ASCII, so a value holding one is a value in neither form —
    /// which is this rule's own finding, and the one it reports now.
    #[test]
    /// The octet is not a claim about the field's encoding: every octet
    /// either the Structured Field Date or the legacy HTTP-date prints is
    /// visible US-ASCII, so a value holding one is in neither form — which is
    /// this rule's own finding, and the one it makes now.
    fn an_obs_text_octet_is_a_value_in_neither_form() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("deprecation", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

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
        assert_eq!(
            v.message,
            "Deprecation value '\u{ff}' is invalid: must be a structured Date item \
             (e.g., '@1688169599') per RFC 9745"
        );
        Ok(())
    }

    #[test]
    fn whitespace_trim_valid_and_no_violation() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "   @1688169599   ")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn starts_with_at_but_nondigits_is_invalid() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "@abc")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid"));
        assert!(msg.contains("@abc"));
        Ok(())
    }

    #[test]
    fn single_at_is_invalid() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("deprecation", "@")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn uppercase_true_reports_legacy() -> anyhow::Result<()> {
        let rule = DeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "TRUE")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("'true'"));
        Ok(())
    }

    #[test]
    fn no_response_no_violation() {
        let rule = DeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn needs_a_response() {
        let rule = DeprecationHeaderSyntax;
        assert!(rule.needs_response());
    }
}
