// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::http_date::{
    http_date_defect, HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_EMPTY, HTTP_DATE_MALFORMED,
    HTTP_DATE_OBSOLETE, RFC_5322_3_3, RFC_9110_5_6_7,
};
use crate::violations::ViolationDef;

/// The two conditional request fields defined as `HTTP-date`, and the one
/// sender's obligation between them.
///
/// `If-Modified-Since` (RFC 9110 § 13.1.3) and `If-Unmodified-Since` (§ 13.1.4)
/// are each `HTTP-date`; a sender must generate one as an IMF-fixdate (§ 5.6.7).
/// This checks that obligation, for both.
///
/// **They were two rules until they declared their defects.** The two files
/// differed in the field name and the section number and in nothing else that
/// ran — one of them said so, deferring its own `OWS` reasoning to "the sibling
/// `if_modified_since_date_syntax`". *A comment pointing at another file for
/// why this file does what it does is a merge that has already happened in
/// prose*, and the defect lists agreed: the same four ids, twice.
///
/// What is *not* merged is the direction the comparison runs. That is the
/// server's question and `conditional_headers_consistent` asks it; the value
/// these two fields carry is one production and does not know which way it will
/// be read.
pub struct ConditionalDateSyntax;

/// The two ways a timestamp fails, which are the production's rather than
/// either field's. Both fields are `HTTP-date` and a request is a sender, so
/// the same pair `Last-Modified` reports answers here — the obsolete formats a
/// recipient must accept and a sender may not write, and the value no format
/// parses at all.
///
/// What stays on the older API is what a *conditional* field says about itself:
/// a value that is only whitespace, and one carrying octets outside visible
/// US-ASCII. `Last-Modified` declares neither, because a response may omit the
/// field and a blank line is not a client that meant to condition.
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
    &HTTP_DATE_EMPTY,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
];

/// The two fields, each with the spelling a finding names it by. Header lookup
/// is lowercase; a message is read by a person, so it says `If-Modified-Since`.
const FIELDS: &[(&str, &str)] = &[
    ("if-modified-since", "If-Modified-Since"),
    ("if-unmodified-since", "If-Unmodified-Since"),
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
///
/// **Both field sections are here and neither is cited**, for the same reason
/// as `conditional_etag_syntax`: they print the same production for their own
/// field, so which one governs a finding depends on which field carried it —
/// and a citation comes off the def, which names § 5.6.7, where the sender's
/// obligation is actually written.
const RFC_9110_13_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "If-Modified-Since header",
};

const RFC_9110_13_1_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4",
    note: "If-Unmodified-Since header",
};

impl RuleMeta for ConditionalDateSyntax {
    fn id(&self) -> &'static str {
        "conditional_date_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Conditional Date Format")
    }

    fn description(&self) -> &'static str {
        "The `If-Modified-Since` (RFC 9110 §13.1.3) and `If-Unmodified-Since` (§13.1.4) request headers are each defined as an HTTP-date, and a sender MUST generate one in the IMF-fixdate format. This rule reads both against that one obligation: it flags values that are not a valid IMF-fixdate — including the two obsolete formats, which a recipient must still accept but no sender may emit — and reads each value as octets, so an octet outside visible US-ASCII is reported as a character the format does not print rather than as a verdict about the field's encoding. Which direction the comparison then runs is the server's question, not the value's."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_13_1_3,
            RFC_9110_13_1_4,
            RFC_9110_5_6_7,
            RFC_5322_3_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nIf-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nIf-Modified-Since: not-a-date",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet:
                    "PUT /resource HTTP/1.1\nIf-Unmodified-Since: Sunday, 06-Nov-94 08:49:37 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "PUT /resource HTTP/1.1\nIf-Unmodified-Since: \\xff",
            },
        ]
    }
}

impl ConditionalDateSyntax {
    /// The whole reading, for one of the two fields.
    ///
    /// A field at a time, because a request may carry both and each is its own
    /// value: a malformed `If-Modified-Since` says nothing about the
    /// `If-Unmodified-Since` beside it, and reporting only the first would make
    /// the second's silence depend on the order this rule happens to look in.
    fn field_finding(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        ctx: &crate::rules::RuleContext<'_>,
        lowercase: &str,
        shown: &str,
    ) -> Option<Violation> {
        // Applies to requests only. Each field line is its own timestamp — this
        // is not a list construct — so they are read one at a time and the
        // first defect ends the field.
        for hv in tx.request.headers.get_all(lowercase).iter() {
            // Read as octets. Every octet an `IMF-fixdate` prints is
            // visible US-ASCII — three letters, a comma, digits and
            // `SP` — so the string reader's refusal and the format's
            // are the same refusal, and only one of them can name the
            // character. The value goes to the reader that owns the
            // production.
            let s = crate::helpers::headers::field_line_as_written(hv);
            let s = s.as_str();

            // `OWS` here too, so this branch and the one below agree about what
            // whitespace is. `str::trim` would call an `obs-text` octet whitespace
            // and say "contains only whitespace" about a value holding one.
            // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
            if crate::helpers::headers::trim_ows(s).is_empty() {
                return Some(ctx.report_with(
                    &HTTP_DATE_EMPTY,
                    format!("{shown} header is empty or contains only whitespace"),
                ));
            }

            // The field is defined as HTTP-date, which is the grammar; it is not the
            // licence. A request is generated by a sender, and a sender is confined to
            // IMF-fixdate, so the obsolete two are violations here even though we are
            // obliged to parse them.
            // The trim is `OWS` and it is this side's, not the date reader's.
            // `IMF-fixdate` prints no whitespace beyond the `SP`s at its fixed
            // offsets, so the validator measures whatever it is handed; what
            // makes a leading or trailing `OWS` not part of *this* value is the
            // `field-line` production and § 5.5's sentence about it, which is a
            // fact about the field line rather than about the date.
            //
            // cite(RFC 9110 § 13.1.3): "If-Modified-Since = HTTP-date"
            // cite(RFC 9110 § 13.1.4): "If-Unmodified-Since = HTTP-date"
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace"
            // cite(RFC 9112 § 5): "field-line   = field-name ":" OWS field-value OWS"
            // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
            if let Err(defect) =
                crate::http_date::check_imf_fixdate(crate::helpers::headers::trim_ows(s))
            {
                // As at every other site reading this production: the weekday
                // that is not the day its date implies derives from the
                // grammar, so it does not take the grammar's sentence.
                return Some(ctx.report_with(
                    http_date_defect(defect),
                    match defect {
                        crate::http_date::HttpDateDefect::DayNameConflicting => format!(
                            "{shown} header names a weekday its own date does not fall on \
                             (RFC 9110 §5.6.7, RFC 5322 §3.3)"
                        ),
                        _ => format!("{shown} header is not a valid IMF-fixdate (RFC 9110 §5.6.7)"),
                    },
                ));
            }
        }

        None
    }
}

impl Rule for ConditionalDateSyntax {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        FIELDS
            .iter()
            .filter_map(|(lowercase, shown)| self.field_finding(tx, ctx, lowercase, shown))
            .collect()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalDateSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every case is asked of both fields, because the point of the merge is
    /// that there is one answer: two rules used to hold two copies of this
    /// table and nothing compared them.
    #[rstest]
    #[case(Some("Wed, 21 Oct 2015 07:28:00 GMT"), false)]
    #[case(Some("not-a-date"), true)]
    // RFC 9110 § 5.6.7's own examples of the two obsolete formats. A recipient must
    // accept both; a sender may generate neither, and a request is sent by a sender.
    #[case(Some("Sunday, 06-Nov-94 08:49:37 GMT"), true)]
    #[case(Some("Sun Nov  6 08:49:37 1994"), true)]
    // The `OWS` a `field-line` may carry around its value. `is_valid_imf_fixdate`
    // measures the whole string now, so excluding this is the rule's own step and
    // deleting it would report a sender for what RFC 9112 § 5 lets it write.
    #[case(Some(" Wed, 21 Oct 2015 07:28:00 GMT"), false)]
    #[case(Some("Wed, 21 Oct 2015 07:28:00 GMT\t"), false)]
    #[case(Some(""), true)]
    #[case(None, false)]
    fn both_fields_read_the_same_obligation(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
        #[values("if-modified-since", "if-unmodified-since")] field: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, h)]);
        }

        let v = crate::test_helpers::run_rule(
            &ConditionalDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_date_syntax"]),
        );
        assert_eq!(v.is_some(), expect_violation, "{field}={header:?}: {v:?}");
    }

    /// The two fields are two values, and a defect in one says nothing about
    /// the other. This is what the merge had to keep: two rules reported these
    /// independently because they were two dispatches, and one rule reports
    /// them independently because it reads a field at a time.
    #[test]
    fn each_field_is_read_on_its_own() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-modified-since", "not-a-date"),
            ("if-unmodified-since", "Sun Nov  6 08:49:37 1994"),
        ]);

        let found = crate::test_helpers::run_rule_all(
            &ConditionalDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_date_syntax"]),
        );
        let seen: Vec<(&str, &str)> = found
            .iter()
            .map(|v| (v.violation.as_str(), v.message.as_str()))
            .collect();
        assert_eq!(found.len(), 2, "{seen:?}");
        // Two fields, two defects: the unreadable value and the obsolete
        // format, each named for the field that carried it.
        assert_eq!(found[0].violation, "http_date_malformed", "{seen:?}");
        assert!(
            found[0].message.starts_with("If-Modified-Since header"),
            "{seen:?}",
        );
        assert_eq!(found[1].violation, "http_date_obsolete", "{seen:?}");
        assert!(
            found[1].message.starts_with("If-Unmodified-Since header"),
            "{seen:?}",
        );
    }

    /// An octet outside visible US-ASCII is a character the format does not
    /// print, so the value is read as octets and the finding is about the
    /// timestamp rather than about an encoding.
    #[test]
    fn non_utf8_header_value_is_violation() {
        use hyper::header::{HeaderName, HeaderValue};

        for field in ["if-modified-since", "if-unmodified-since"] {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers.insert(
                HeaderName::from_bytes(field.as_bytes()).expect("a field name"),
                HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header"),
            );

            let v = crate::test_helpers::run_rule(
                &ConditionalDateSyntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "conditional_date_syntax",
                ]),
            );
            assert!(v.is_some(), "{field}");
        }
    }

    /// A blank value names its own defect rather than falling through to the
    /// format reader, and the message says which field was blank.
    #[test]
    fn empty_header_value_reports_violation() {
        for (field, shown) in FIELDS {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(*field, "")]);

            let v = crate::test_helpers::run_rule(
                &ConditionalDateSyntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "conditional_date_syntax",
                ]),
            )
            .unwrap_or_else(|| panic!("expected a violation for an empty {shown}"));
            assert_eq!(v.violation, "http_date_empty");
            assert!(
                v.message == format!("{shown} header is empty or contains only whitespace"),
                "{}",
                v.message,
            );
        }
    }

    /// Repeating one of these fields is not a list construct: each field line
    /// is its own timestamp, so every line is read and one bad line is
    /// reported. (Whether a repeat is *allowed* is
    /// `conditional_headers_consistent`'s question.)
    #[rstest]
    #[case("Wed, 02 Jan 2030 12:00:00 GMT", false)]
    #[case("not-a-date", true)]
    fn every_field_line_is_read(
        #[case] second: &str,
        #[case] expect_violation: bool,
        #[values("if-modified-since", "if-unmodified-since")] field: &str,
    ) {
        use hyper::header::{HeaderName, HeaderValue};
        let name = HeaderName::from_bytes(field.as_bytes()).expect("a field name");
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            name.clone(),
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        tx.request
            .headers
            .append(name, HeaderValue::from_str(second).expect("a test value"));

        let v = crate::test_helpers::run_rule(
            &ConditionalDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_date_syntax"]),
        );
        assert_eq!(v.is_some(), expect_violation, "{field}: {v:?}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_date_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = ConditionalDateSyntax;
        assert_eq!(r.id(), "conditional_date_syntax");
        assert!(!r.needs_response());
    }
}
