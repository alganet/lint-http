// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::http_date::{
    http_date_defect, HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_EMPTY, HTTP_DATE_MALFORMED,
    HTTP_DATE_OBSOLETE, RFC_5322_3_3, RFC_9110_5_6_7,
};
use crate::violations::ViolationDef;

pub struct LastModifiedRfc1123Syntax;

/// The one defect this rule reports about the timestamp, split in two by the
/// production it is written in. `Last-Modified = HTTP-date`, so a value that
/// parses as none of the three formats and a value written in one of the two a
/// sender may not generate are the two ways the field fails — and the same two
/// ways `If-Modified-Since` and `If-Unmodified-Since` fail, which is why the ids
/// name the timestamp and not the field.
///
/// The non-UTF-8 line stays on the older API: the verdict names an encoding
/// where the defect is an octet the field's grammar does not admit, and the
/// right conversion for such a site is an octet-wise reader before a def.
///
/// **`http_date_whitespace_forbidden` is not among them, and the reading is
/// § 5.5's.** That entry reports an `IMF-fixdate` carrying octets the
/// production never prints — but the `OWS` around a *field value* is not part
/// of it, and the reading below excludes it before measuring, so no field line
/// can produce the padding it names. It belongs to the one site where a
/// timestamp arrives quoted inside a larger value: a `Warning`'s `warn-date`.
/// Declaring it here published a verdict this rule has never been able to
/// reach.
static DECLARED: &[&ViolationDef] = &[
    &HTTP_DATE_MALFORMED,
    &HTTP_DATE_OBSOLETE,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
    &HTTP_DATE_EMPTY,
];

impl RuleMeta for LastModifiedRfc1123Syntax {
    fn id(&self) -> &'static str {
        "last_modified_rfc1123_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Last-Modified RFC 1123 Format")
    }

    fn description(&self) -> &'static str {
        "Verifies that the `Last-Modified` header (when present) uses the IMF-fixdate format (a.k.a. RFC 1123 date) as required by HTTP date formatting rules."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_5_6_7, RFC_5322_3_3]
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
                snippet: "HTTP/1.1 200 OK\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nLast-Modified: 2015-10-21T07:28:00Z\nContent-Type: text/plain\n\nHello",
            },
        ]
    }
}

impl Rule for LastModifiedRfc1123Syntax {
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
            let Some(resp) = &tx.response else {
                return None;
            };

            // Read as octets rather than through the string reader. Every
            // octet an `IMF-fixdate` prints is visible US-ASCII, so the
            // reader's refusal and the format's are the same refusal said
            // twice -- and only the format's can name the character.
            if let Some(hv) = resp.headers.get("last-modified") {
                let s = crate::helpers::headers::field_line_as_written(hv);
                let s = s.as_str();
                // A response is a sender, so HTTP-date is not the bar here: the field is
                // *defined* as HTTP-date, and a sender is still confined to IMF-fixdate.
                // Checking `is_valid_http_date` accepted the two obsolete formats and so
                // could never fail on the thing this rule exists to report.
                // The `OWS` is excluded here, because only this side knows the value
                // came off a field line. `IMF-fixdate` prints no whitespace but the
                // `SP`s at its fixed offsets and § 5.6.7 forbids a sender any more,
                // so `is_valid_imf_fixdate` measures whatever it is handed; what
                // makes a leading or trailing `OWS` not part of *this* value is the
                // `field-line` production and § 5.5's sentence about it, and the
                // trim is `OWS` rather than `str::trim` for the reason recorded at
                // `trim_ows`.
                //
                // cite(RFC 9110 § 8.8.2): "Last-Modified = HTTP-date"
                // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace"
                // cite(RFC 9112 § 5): "field-line   = field-name ":" OWS field-value OWS"
                // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
                if let Err(defect) =
                    crate::http_date::check_imf_fixdate(crate::helpers::headers::trim_ows(s))
                {
                    // The day-name is the one defect whose sentence cannot be
                    // the field's usual one: the value *is* an IMF-fixdate by
                    // the production, and what it gets wrong is the weekday.
                    return Some(ctx.report_with(
                        http_date_defect(defect),
                        match defect {
                            crate::http_date::HttpDateDefect::DayNameConflicting => {
                                "Last-Modified header names a weekday its own date does not fall on"
                            }
                            crate::http_date::HttpDateDefect::Empty => {
                                "Last-Modified header is empty or contains only whitespace"
                            }
                            _ => "Last-Modified header is not a valid IMF-fixdate (RFC 9110)",
                        }
                        .into(),
                    ));
                }
            }
            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &LastModifiedRfc1123Syntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Three fields, one production, three ids — and the split a `bool` could
    /// not make. `Sunday, 06-Nov-94 08:49:37 GMT` names the instant it means and
    /// every recipient must read it, so the sender's MUST NOT is reported at
    /// `info`; `not-a-date` names nothing, and sits above it. The two
    /// conditional fields answer the same way, which is what the shared subject
    /// buys.
    #[test]
    fn a_timestamp_fails_in_three_ways_and_three_fields_agree() {
        let last_modified = |value: &str| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("last-modified", value)]);
            crate::test_helpers::run_rule(
                &LastModifiedRfc1123Syntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "last_modified_rfc1123_syntax",
                ]),
            )
            .expect("a finding")
        };

        let obsolete = last_modified("Sunday, 06-Nov-94 08:49:37 GMT");
        assert_eq!(obsolete.violation, "http_date_obsolete");
        assert_eq!(obsolete.severity, crate::lint::Severity::Error);

        let unreadable = last_modified("not-a-date");
        assert_eq!(unreadable.violation, "http_date_malformed");
        assert_eq!(unreadable.severity, crate::lint::Severity::Error);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-modified-since", "Sun Nov  6 08:49:37 1994"),
            ("if-unmodified-since", "Sun Nov  6 08:49:37 1994"),
        ]);
        let rule = crate::rules::all_rules()
            .find(|r| r.id() == "conditional_date_syntax")
            .expect("a registered rule");
        assert_eq!(
            rule.violations().iter().map(|d| d.id).collect::<Vec<_>>(),
            vec![
                "http_date_malformed",
                "http_date_obsolete",
                // The two conditional fields report an empty value where
                // `Last-Modified` does not: a request may leave the field
                // out, so a line with nothing on it is a client that meant
                // to condition and did not.
                "http_date_empty",
                // And the fourth answer the shared reader gained: a weekday
                // that is not the day its own date falls on. Both conditional
                // fields carry it for the same reason `Last-Modified` does —
                // one production, one reader, one id.
                "http_date_day_name_conflicting",
            ],
        );
        let conditional = crate::test_helpers::run_rule(
            &crate::rules::conditional_date_syntax::ConditionalDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_date_syntax"]),
        )
        .expect("a finding");
        assert_eq!(conditional.violation, obsolete.violation);
    }

    /// `Last-Modified` and the two conditional fields answer the fourth way a
    /// timestamp fails the same way they answer the other three, because the
    /// reader is one reader. The value is a real one: GitHub's `Expires` is
    /// `Fri, 01 Jan 1980 00:00:00 GMT`, and the first of January 1980 was a
    /// Tuesday.
    #[test]
    fn a_weekday_the_date_does_not_imply_is_its_own_id_in_all_three_fields() {
        let last_modified = |value: &str| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("last-modified", value)]);
            crate::test_helpers::run_rule(
                &LastModifiedRfc1123Syntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "last_modified_rfc1123_syntax",
                ]),
            )
            .expect("a finding")
        };
        let here = last_modified("Fri, 01 Jan 1980 00:00:00 GMT");
        assert_eq!(here.violation, "http_date_day_name_conflicting");
        assert_eq!(here.severity, crate::lint::Severity::Error);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-modified-since", "Fri, 01 Jan 1980 00:00:00 GMT"),
            ("if-unmodified-since", "Fri, 01 Jan 1980 00:00:00 GMT"),
        ]);
        let conditional = crate::test_helpers::run_rule(
            &crate::rules::conditional_date_syntax::ConditionalDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_date_syntax"]),
        )
        .expect("a finding");
        assert_eq!(conditional.violation, here.violation);
    }

    /// The padding a field line may carry is not the padding
    /// `http_date_whitespace_forbidden` names, and this is what holds that rule
    /// off the entry: § 5.5 puts the `OWS` outside the value, the reading
    /// excludes it, and what is left is the format § 5.6.7 asked for.
    #[rstest]
    #[case(" Wed, 21 Oct 2015 07:28:00 GMT")]
    #[case("Wed, 21 Oct 2015 07:28:00 GMT\t")]
    fn a_field_line_cannot_carry_the_padding_the_whitespace_entry_names(#[case] value: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("last-modified", value)]);
        assert!(
            crate::test_helpers::run_rule(
                &LastModifiedRfc1123Syntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "last_modified_rfc1123_syntax",
                ]),
            )
            .is_none(),
            "{value:?}",
        );

        let mut request = crate::test_helpers::make_test_transaction();
        request.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-modified-since", value)]);
        assert!(
            crate::test_helpers::run_rule(
                &crate::rules::conditional_date_syntax::ConditionalDateSyntax,
                &request,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "conditional_date_syntax",
                ]),
            )
            .is_none(),
            "{value:?}",
        );
    }

    #[rstest]
    #[case(Some(vec![("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(Some(vec![("last-modified", "not-a-date")] ), true)]
    #[case(Some(vec![("last-modified", "Wed, 02 Jan 2030 12:00:00 GMT")] ), false)]
    #[case(None, false)]
    // The two obsolete formats, in RFC 9110 § 5.6.7's own words. A recipient must
    // accept both; a sender may generate neither, and a response is a sender. These
    // are the cases this rule advertised and could not catch until it stopped asking
    // the recipient's question.
    #[case(Some(vec![("last-modified", "Sunday, 06-Nov-94 08:49:37 GMT")] ), true)]
    #[case(Some(vec![("last-modified", "Sun Nov  6 08:49:37 1994")] ), true)]
    // The `OWS` a `field-line` is allowed to carry around its value, which is
    // this side's to exclude now that `is_valid_imf_fixdate` measures the whole
    // string. Reporting these would report an HTTP/1.1 sender for something
    // RFC 9112 § 5 lets it write — and hyper's own parser has already removed
    // them from live traffic, so what this pins is the capture-file path.
    //
    // What these two guard is the `trim_ows` call, not the whole change: they
    // fail if it is deleted and pass if the trim moves back inside the date
    // reader, because both spellings tolerate the padding. That is the guard
    // worth having, since the call is the load-bearing half here.
    #[case(Some(vec![("last-modified", " Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(Some(vec![("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT\t")] ), false)]
    fn check_last_modified_cases(
        #[case] headers: Option<Vec<(&str, &str)>>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = LastModifiedRfc1123Syntax;
        let mut tx = crate::test_helpers::make_test_transaction();

        if let Some(h) = headers {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&h),

                body_length: None,
                body_interrupted: false,
                trailers: None,
            });
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Last-Modified"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    /// An octet outside visible US-ASCII is a character `IMF-fixdate` does
    /// not print, which is what the format reader reports it as — the value is
    /// no longer refused before the format is consulted.
    fn an_obs_text_octet_is_a_timestamp_defect() -> anyhow::Result<()> {
        let rule = LastModifiedRfc1123Syntax;
        let mut tx = crate::test_helpers::make_test_transaction();

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("last-modified", bad);
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
        assert_eq!(v.violation, "http_date_malformed");
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = LastModifiedRfc1123Syntax;
        assert!(rule.needs_response());
    }
}
