// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_length::{
    content_length_defect, CONTENT_LENGTH_CHARACTER_FORBIDDEN, CONTENT_LENGTH_EMPTY,
    CONTENT_LENGTH_MEMBERS_CONFLICTING, CONTENT_LENGTH_NUMERAL_INVALID, RFC_9110_8_6, RFC_9112_6_3,
};
use crate::violations::ViolationDef;

pub struct ContentLengthValid;

/// Everything this rule reports, and all of it belongs to the field rather than
/// to this reading of it.
///
/// The messages come from `validate_content_length`, which four other rules
/// call as a gate — so the defects are the *helper's* and the subject is the
/// field's, not this rule's. What is left here is the claim that a malformed or
/// self-contradictory `Content-Length` is worth reporting wherever it appears,
/// which is why the rule reads both directions and cites the sentence saying
/// the field describes a representation rather than a direction.
static DECLARED: &[&ViolationDef] = &[
    &CONTENT_LENGTH_EMPTY,
    &CONTENT_LENGTH_CHARACTER_FORBIDDEN,
    &CONTENT_LENGTH_NUMERAL_INVALID,
    &CONTENT_LENGTH_MEMBERS_CONFLICTING,
];

impl RuleMeta for ContentLengthValid {
    fn id(&self) -> &'static str {
        "content_length_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Length")
    }

    fn description(&self) -> &'static str {
        "This rule validates `Content-Length` header values for syntax and consistency:\n\n- Each `Content-Length` header value must be a non-negative decimal integer (no signs, no decimals).\n- A `Content-Length` header with an empty value or containing non-digit characters is invalid.\n- When multiple `Content-Length` header fields are present, their trimmed numeric values MUST be identical.\n\nThe field lines are read as the octets the sender wrote, so an octet outside US-ASCII is reported as the character `DIGIT` does not admit rather than as a verdict about the value's encoding — the whole production is ten visible US-ASCII characters, so there was never anything for the encoding to say first.\n\nImproper `Content-Length` values can lead to message framing errors or truncated bodies; the rule flags invalid or inconsistent values."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_6, RFC_9112_6_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Length: 0\nContent-Length: 10\nContent-Length:  20  \n\nContent-Length: 10\nContent-Length:  10 ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Length: -1\nContent-Length: +1\nContent-Length: 1.5\nContent-Length: abc\nContent-Length:\n\nContent-Length: 10\nContent-Length: 20",
            },
        ]
    }
}

impl Rule for ContentLengthValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // The field is defined by what it describes, not by direction, so it is checked
            // on both sides below. The `1*DIGIT` grammar and the §6.3 comma-list rule are
            // deliberately *not* re-quoted here: `validate_content_length` owns both, and a
            // second copy of a helper's production is the duplicate-transcription trap.
            // What this rule keeps is its own claim — that a malformed or self-contradictory
            // Content-Length is worth reporting wherever it appears.
            // cite(RFC 9110 § 8.6): "The "Content-Length" header field indicates the associated representation's data length as a decimal non-negative integer number of octets."
            let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
                match crate::helpers::content_length::validate_content_length(headers) {
                    Ok(_) => None,
                    Err(e) => {
                        // The format strings stay where their arguments are; the
                        // id comes from the helper's subject, because the helper
                        // is what four other rules read this field through.
                        let message = match &e {
                            crate::helpers::content_length::ContentLengthError::Empty => {
                                "Content-Length carries no digits".into()
                            }
                            crate::helpers::content_length::ContentLengthError::InvalidCharacter(c, s) => {
                                format!(
                                    "Invalid Content-Length value '{}': contains {}",
                                    crate::helpers::shown::shown_in_finding(s),
                                    crate::helpers::shown::describe_char(*c),
                                )
                            }
                            crate::helpers::content_length::ContentLengthError::TooLarge(s) => {
                                format!("Content-Length value too large: '{}'", s)
                            }
                            crate::helpers::content_length::ContentLengthError::MultipleValuesDiffer(
                                a,
                                b,
                            ) => {
                                format!(
                                    "Multiple Content-Length headers with differing values: '{}' vs '{}'",
                                    a, b
                                )
                            }
                        };

                        Some(ctx.report_with(content_length_defect(&e), message))
                    }
                }
            };

            // Request
            if let Some(v) = check(&tx.request.headers) {
                return Some(v);
            }

            // Response
            if let Some(resp) = &tx.response {
                if let Some(v) = check(&resp.headers) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentLengthValid;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("0", false)]
    #[case("  20  ", false)]
    #[case("", true)]
    #[case("abc", true)]
    #[case("-1", true)]
    #[case("+1", true)]
    #[case("1.5", true)]
    #[case("340282366920938463463374607431768211456", true)]
    fn check_single_request_values(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentLengthValid;

        let tx =
            crate::test_helpers::make_test_transaction_with_headers(&[("content-length", value)]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "value '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "value '{}' expected no violation", value);
        }

        Ok(())
    }

    #[rstest]
    #[case("0", false)]
    #[case("  20  ", false)]
    #[case("", true)]
    #[case("abc", true)]
    #[case("-1", true)]
    #[case("+1", true)]
    #[case("1.5", true)]
    fn check_single_response_values(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentLengthValid;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-length", value)],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "response value '{}' expected violation", value);
        } else {
            assert!(
                v.is_none(),
                "response value '{}' expected no violation",
                value
            );
        }

        Ok(())
    }

    #[rstest]
    #[case(vec!["10", " 10 "], false)]
    #[case(vec!["10", "20"], true)]
    fn check_multiple_values(
        #[case] values: Vec<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentLengthValid;

        // request
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-length", *v)).collect();
        let tx = crate::test_helpers::make_test_transaction_with_headers(&pairs);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "request values '{:?}' expected violation",
                values
            );
        } else {
            assert!(
                v.is_none(),
                "request values '{:?}' expected no violation",
                values
            );
        }

        // response
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm2 = hyper::HeaderMap::new();
        for v in &values {
            hm2.append(hyper::header::CONTENT_LENGTH, HeaderValue::from_str(v)?);
        }
        tx2.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm2,
            body_length: None,
            trailers: None,
        });

        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v2.is_some(),
                "response values '{:?}' expected violation",
                values
            );
        } else {
            assert!(
                v2.is_none(),
                "response values '{:?}' expected no violation",
                values
            );
        }

        Ok(())
    }

    /// The octet is the alphabet's defect and the finding names it. It used to
    /// be reported as a verdict about the value's encoding, which said nothing
    /// about which octet arrived — and `DIGIT` had already refused it, because
    /// the whole production is visible US-ASCII.
    #[test]
    fn an_octet_outside_us_ascii_is_named_rather_than_called_an_encoding() -> anyhow::Result<()> {
        let rule = ContentLengthValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        let bad_value = HeaderValue::from_bytes(&[0xFF])?;
        hm.insert(hyper::header::CONTENT_LENGTH, bad_value);
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "content_length_character_forbidden");
        assert_eq!(
            v.message, "Invalid Content-Length value 'ÿ': contains 0xFF",
            "the octet is named, and the value is shown as it was written",
        );
        Ok(())
    }

    /// Four ways to get the framing wrong, four ids, and three of them outrank
    /// the fourth: the overlong numeral is the one no sentence refuses, so it
    /// stays `warn` while the rest are `error`. One rule severity said all four
    /// at once.
    #[test]
    fn each_defect_is_the_fields_and_carries_its_own_rank() {
        for (value, id, severity) in [
            ("", "content_length_empty", crate::lint::Severity::Error),
            (
                "1.5",
                "content_length_character_forbidden",
                crate::lint::Severity::Error,
            ),
            (
                "340282366920938463463374607431768211456",
                "content_length_numeral_invalid",
                crate::lint::Severity::Warn,
            ),
            (
                "10, 20",
                "content_length_members_conflicting",
                crate::lint::Severity::Error,
            ),
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
                "content-length",
                value,
            )]);
            let found = crate::test_helpers::run_rule(
                &ContentLengthValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "content_length_valid",
                ]),
            )
            .unwrap_or_else(|| panic!("{value:?}"));
            assert_eq!(found.violation, id, "{value:?}");
            assert_eq!(found.severity, severity, "{value:?}");
        }
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentLengthValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
