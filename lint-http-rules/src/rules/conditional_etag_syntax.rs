// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::CONDITIONAL_EMPTY;
use crate::violations::etag::{
    entity_tag_defect, ETAG_CHARACTER_FORBIDDEN, ETAG_DELIMITER_MISSING,
    ETAG_WEAK_INDICATOR_INVALID, RFC_9110_8_8_3,
};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::ViolationDef;

/// The production's three defects, borrowed whole.
///
/// Each field is `"*" / #entity-tag`: the `*` is the other alternative and the
/// members are § 8.8.3's production, restated nowhere. So a member that is not
/// a tag draws the same id an `ETag` carrying the same value draws, and what
/// stays this rule's own is the alternation — a `*` written as a member rather
/// than as the whole value — and the empty list element the list construct
/// forbids.
static DECLARED: &[&ViolationDef] = &[
    &ETAG_WEAK_INDICATOR_INVALID,
    &ETAG_DELIMITER_MISSING,
    &ETAG_CHARACTER_FORBIDDEN,
    &CONDITIONAL_EMPTY,
    &LIST_MEMBER_EMPTY,
];

/// The two conditional request fields written as `"*" / #entity-tag`, and the
/// one grammar between them.
///
/// **They were two rules until they declared their defects.** `If-Match` and
/// `If-None-Match` were read by two files that differed in the field name, the
/// section number, and a comment about which comparison function the *server*
/// then applies — which neither rule performs. Once each named the defects it
/// reports, the two lists were the same five ids, and there was nothing left an
/// operator could tell apart except which rule id a finding arrived under.
///
/// What is *not* merged is the evaluation. `conditional_headers_consistent`
/// and `conditional_request_handling` read what a server did with these fields;
/// this reads whether the client wrote one that derives from the production.
pub struct ConditionalEtagSyntax;

/// The two fields, each with the spelling a finding names it by. Header lookup
/// is lowercase; a message is read by a person, so it says `If-Match`.
const FIELDS: &[(&str, &str)] = &[("if-match", "If-Match"), ("if-none-match", "If-None-Match")];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
///
/// **The two field sections are both here and neither is cited.** § 13.1.1 and
/// § 13.1.2 print the same production for their own field, so a finding about
/// the alternation is governed by whichever field carried it — which is a
/// per-finding choice, and `report_with` carries a citation off the *def*. The
/// def names § 8.8.3, where the members are actually written, and these two sit
/// in `specifications()` as the further reading a doc page owes.
const RFC_9110_13_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1",
    note: "If-Match",
};

const RFC_9110_13_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2",
    note: "If-None-Match",
};

impl RuleMeta for ConditionalEtagSyntax {
    fn id(&self) -> &'static str {
        "conditional_etag_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Conditional ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "`If-Match` (RFC 9110 §13.1.1) and `If-None-Match` (§13.1.2) are each either `*` or a comma-separated list of entity-tags, and this rule reads both against that one production. **The two alternatives are alternatives**, so the `*` is the whole field value: `If-Match: \"abc\", *` derives from neither and is reported, and because a repeated field name makes one value (§5.2), so does the same pair written on two field lines. `etagc` admits the comma, so a tag such as `\"a,b\"` is one member and not two. Each entity-tag follows the grammar in RFC 9110 §8.8.3 and may be weak (prefix `W/`); a weak tag is valid syntax in both fields, whichever comparison function the server then applies. This rule validates that field syntax (quoting, escaping, and prohibition of control characters); it neither flags weak tags nor performs the comparison."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_8_3,
            RFC_9110_13_1_1,
            RFC_9110_13_1_2,
            RFC_9110_5_6_1_1,
        ]
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
                snippet: "PUT /resource HTTP/1.1\nHost: example.com\nIf-Match: \"abc123\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: W/\"weaktag\", \"strong\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "PUT /resource HTTP/1.1\nHost: example.com\nIf-Match: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "PUT /resource HTTP/1.1\nHost: example.com\nIf-Match: abc123   # missing quotes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: W/abc    # missing quoted-string after W/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"unterminated",
            },
        ]
    }
}

impl ConditionalEtagSyntax {
    /// The whole reading, for one of the two fields.
    ///
    /// A field at a time, because a request may carry both and each is its own
    /// value: a malformed `If-Match` says nothing about the `If-None-Match`
    /// beside it, and reporting only the first would make the second's silence
    /// depend on the order this rule happens to look in.
    fn field_finding(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        ctx: &crate::rules::RuleContext<'_>,
        lowercase: &str,
        shown: &str,
    ) -> Option<Violation> {
        // Only applies to requests. **One value, however many field lines carry
        // it**: `#entity-tag` is a list, so § 5.2 combines the lines with a
        // comma before the members are counted -- and the alternation above the
        // list is decided on the value those lines make, not on one of them.
        // Octet-level, because an `obs-text` octet is a member this rule can
        // measure and `to_str` would fold it into "no such field here".
        //
        // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
        let value = crate::helpers::headers::combined_field_value_as_written(
            &tx.request.headers,
            lowercase,
        )?;
        let value = crate::helpers::headers::trim_ows(&value);

        // The field is `*` **or** a comma-separated list of entity-tags, and the
        // two are alternatives: `*` is the whole field value and is not a member
        // the list may hold. It was asked of each member instead -- through
        // `check_entity_tag`, which used to admit it -- so `If-Match:
        // "abc", *` derived from neither alternative and passed as a conforming
        // list. `entity-tag` has no `*` in it; § 13.1.1 and § 13.1.2 are where
        // the `*` lives, one per field, and this is the construct they govern.
        // Syntax-only: a *weak* tag is valid in both (§8.8.3) whatever
        // comparison the server then applies, so weak tags are accepted, not
        // flagged.
        //
        // cite(RFC 9110 § 13.1.1): "If-Match = "*" / #entity-tag"
        // cite(RFC 9110 § 13.1.2): "If-None-Match = "*" / #entity-tag"
        // cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
        if value == "*" {
            return None;
        }

        // Before the members, because there are none: `#entity-tag` with no
        // minimum admits the empty list, but a conditional naming no validator
        // states no condition, and both rules this one replaces reported it
        // since they were written. Asked of the whole value, where the old
        // `seen_any` flag asked it of a walk that silently dropped every empty
        // member.
        if value.is_empty() {
            return Some(ctx.report_with(
                &CONDITIONAL_EMPTY,
                format!("{shown} header is empty or contains only whitespace"),
            ));
        }

        // The walk is quote-aware, and that is a fix rather than a preference:
        // `etagc` admits the comma, so `"a,b"` is **one** entity-tag, and the
        // naive `split(',')` this used to call cut it into `"a` and `b"` and
        // reported a conforming tag as two malformed ones.
        //
        // cite(RFC 9110 § 8.8.3): "etagc      = %x21 / %x23-7E / obs-text ; VCHAR except double quotes, plus obs-text"
        for member in crate::helpers::list::list_members_as_written(value) {
            // That walk keeps the empty members the old one dropped, and they
            // are a defect rather than noise -- named here so the finding is
            // about the list and not about a quoted-string that is not there.
            // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
            if member.is_empty() {
                return Some(ctx.report_with(
                    &LIST_MEMBER_EMPTY,
                    format!("{shown} header contains an empty list element"),
                ));
            }
            if let Err(defect) = crate::helpers::validator::check_entity_tag(member) {
                return Some(ctx.report_with(
                    entity_tag_defect(defect),
                    format!(
                        "{shown} header has invalid member '{}': {}",
                        crate::helpers::shown::shown_in_finding(member),
                        defect.message()
                    ),
                ));
            }
        }

        None
    }
}

impl Rule for ConditionalEtagSyntax {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

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
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalEtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every case is asked of both fields, because the point of the merge is
    /// that there is one answer: two rules used to hold two copies of this
    /// table and nothing compared them.
    #[rstest]
    #[case(Some("*"), false)]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("W/\"abc\", \"def\""), false)]
    #[case(Some("abc"), true)]
    #[case(Some("W/abc"), true)]
    #[case(Some("\"unterminated"), true)]
    #[case(None, false)]
    fn both_fields_read_the_same_production(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
        #[values("if-match", "if-none-match")] field: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(hv) = header {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, hv)]);
        }

        let v = crate::test_helpers::run_rule(
            &ConditionalEtagSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_etag_syntax"]),
        );
        assert_eq!(v.is_some(), expect_violation, "{field}={header:?}: {v:?}",);
    }

    /// The two fields are two values, and a defect in one says nothing about
    /// the other. This is what the merge had to keep: two rules reported these
    /// independently because they were two dispatches, and one rule reports
    /// them independently because it reads a field at a time.
    #[test]
    fn each_field_is_read_on_its_own() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-match", "abc"),
            ("if-none-match", "\"unterminated"),
        ]);

        let found = crate::test_helpers::run_rule_all(
            &ConditionalEtagSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_etag_syntax"]),
        );
        let messages: Vec<&str> = found.iter().map(|v| v.message.as_str()).collect();
        assert_eq!(found.len(), 2, "{messages:?}");
        assert!(messages[0].starts_with("If-Match header"), "{messages:?}");
        assert!(
            messages[1].starts_with("If-None-Match header"),
            "{messages:?}",
        );
    }

    /// An `obs-text` octet is a member this rule can measure, so the value is
    /// read as octets and the finding is about the member rather than about an
    /// encoding.
    #[test]
    fn non_utf8_header_value_is_violation() {
        use hyper::header::{HeaderName, HeaderValue};

        for field in ["if-match", "if-none-match"] {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers.insert(
                HeaderName::from_bytes(field.as_bytes()).expect("a field name"),
                HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header"),
            );

            let v = crate::test_helpers::run_rule(
                &ConditionalEtagSyntax,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "conditional_etag_syntax",
                ]),
            );
            assert!(v.is_some(), "{field}");
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = ConditionalEtagSyntax;
        assert_eq!(r.id(), "conditional_etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }

    /// **`"*" / #entity-tag` is an alternation.** The `*` is the whole field
    /// value, and it was asked of each member instead -- so a list holding one
    /// derived from neither alternative and passed. The other cases are what
    /// the extraction found beside it: the walk is quote-aware now, an empty
    /// member is named as one, and § 5.2 decides the alternation on the value
    /// the field lines make rather than on any one of them.
    #[rstest]
    #[case(&[&b"*"[..]], None)]
    #[case(&[&b"  *  "[..]], None)]
    #[case(&[&b"\"abc\""[..]], None)]
    // `etagc` admits the comma, so this is one tag; the naive `split(',')` cut it
    // into two members and reported a conforming value.
    #[case(&[&b"\"a,b\""[..]], None)]
    #[case(&[&b"\"abc\", *"[..]], Some("invalid member"))]
    #[case(&[&b"*, \"abc\""[..]], Some("invalid member"))]
    // Two field lines are one value, so neither line is "the whole value".
    #[case(&[&b"\"abc\""[..], &b"*"[..]], Some("invalid member"))]
    #[case(&[&b"*"[..], &b"*"[..]], Some("invalid member"))]
    #[case(&[&b"W/\"a\""[..], &b"\"b\""[..]], None)]
    #[case(&[&b"W/\"a\""[..], &b"b"[..]], Some("invalid member"))]
    #[case(&[&b"\"a\", , \"b\""[..]], Some("empty list element"))]
    #[case(&[&b""[..]], Some("empty or contains only whitespace"))]
    #[case(&[&b","[..]], Some("empty list element"))]
    fn the_wildcard_is_the_whole_field_value_and_not_a_member(
        #[case] lines: &[&[u8]],
        #[case] expected: Option<&str>,
        #[values("if-match", "if-none-match")] field: &str,
    ) {
        use hyper::header::{HeaderName, HeaderValue};
        let mut tx = crate::test_helpers::make_test_transaction();
        for line in lines {
            tx.request.headers.append(
                HeaderName::from_bytes(field.as_bytes()).expect("a field name"),
                HeaderValue::from_bytes(line).expect("a test conditional value"),
            );
        }
        let v = crate::test_helpers::run_rule(
            &ConditionalEtagSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["conditional_etag_syntax"]),
        );
        match expected {
            None => assert!(v.is_none(), "expected silence for {field} {lines:?}: {v:?}"),
            Some(sub) => {
                let v = v.unwrap_or_else(|| panic!("expected a violation for {field} {lines:?}"));
                assert!(v.message.contains(sub), "{}", v.message);
            }
        }
    }
}
