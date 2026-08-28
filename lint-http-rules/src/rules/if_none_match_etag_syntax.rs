// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `If-None-Match` header must be either `*` or a comma-separated list of entity-tags
/// (possibly weak `W/"..."`). Validates the field grammar (RFC 9110 §13.1.2); the
/// entity-tag grammar itself is RFC 9110 §8.8.3, owned by `validate_entity_tag`.
pub struct IfNoneMatchEtagSyntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_8_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3",
    note: "ETag header field",
};
const RFC_9110_13_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2",
    note: "If-None-Match",
};

impl Rule for IfNoneMatchEtagSyntax {
    fn id(&self) -> &'static str {
        "if_none_match_etag_syntax"
    }

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
                "if-none-match",
            )?;
            let value = crate::helpers::headers::trim_ows(&value);

            // The field is `*` **or** a comma-separated list of entity-tags, and the
            // two are alternatives: `*` is the whole field value and is not a member
            // the list may hold. It was asked of each member instead -- through
            // `validate_entity_tag`, which used to admit it -- so `If-None-Match:
            // "abc", *` derived from neither alternative and passed as a conforming
            // list. `entity-tag` has no `*` in it; § 13.1.2's production is where
            // the `*` lives, and this is the construct that production governs.
            // Syntax-only: a *weak* tag is valid here (§8.8.3), and If-None-Match is
            // compared weakly anyway, so weak tags are accepted, not flagged. The
            // weak-comparison MUST is owned by `inm_matches_known`, which performs it.
            //
            // cite(RFC 9110 § 13.1.2): "If-None-Match = "*" / #entity-tag"
            // cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
            if value == "*" {
                return None;
            }

            // Before the members, because there are none: `#entity-tag` with no
            // minimum admits the empty list, but a conditional naming no validator
            // states no condition, and this rule has reported it since it was
            // written. Asked of the whole value, where the old `seen_any` flag asked
            // it of a walk that silently dropped every empty member.
            if value.is_empty() {
                return Some(self.violation(
                    ctx.severity,
                    "If-None-Match header is empty or contains only whitespace".into(),
                ));
            }

            // The walk is quote-aware, and that is a fix rather than a preference:
            // `etagc` admits the comma, so `"a,b"` is **one** entity-tag, and the
            // naive `split(',')` this used to call cut it into `"a` and `b"` and
            // reported a conforming tag as two malformed ones.
            //
            // cite(RFC 9110 § 8.8.3): "etagc      = %x21 / %x23-7E / obs-text ; VCHAR except double quotes, plus obs-text"
            for member in crate::helpers::headers::list_members_as_written(value) {
                // That walk keeps the empty members the old one dropped, and they
                // are a defect rather than noise -- named here so the finding is
                // about the list and not about a quoted-string that is not there.
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                if member.is_empty() {
                    return Some(self.violation(
                        ctx.severity,
                        "If-None-Match header contains an empty list element".into(),
                    ));
                }
                if let Err(msg) = crate::helpers::headers::validate_entity_tag(member) {
                    return Some(self.violation(
                        ctx.severity,
                        format!(
                            "If-None-Match header has invalid member '{}': {}",
                            crate::helpers::headers::shown_in_finding(member),
                            msg
                        ),
                    ));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("If-None-Match ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "`If-None-Match` is either `*` or a comma-separated list of entity-tags (RFC 9110 §13.1.2). **The two are alternatives**, so the `*` is the whole field value: `If-None-Match: \"abc\", *` derives from neither and is reported, and because a repeated field name makes one value (§5.2), so does the same pair written on two field lines. `etagc` admits the comma, so a tag such as `\"a,b\"` is one member and not two. Each entity-tag follows the grammar in RFC 9110 §8.8.3 and may be weak (prefix `W/`); `If-None-Match` is evaluated with the weak comparison function, so weak tags are valid syntax here. This rule validates that field syntax (quoting, escaping, and prohibition of control characters); it does not perform the comparison."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_8_3, RFC_9110_13_1_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc123\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: W/\"weaktag\", \"strong\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: abc123   # missing quotes",
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

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &IfNoneMatchEtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("*"), false)]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("W/\"abc\", \"def\""), false)]
    #[case(Some("abc"), true)]
    #[case(Some("W/abc"), true)]
    #[case(Some("\"unterminated"), true)]
    #[case(None, false)]
    fn if_none_match_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = IfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(hv) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("if-none-match", hv)]);
        }

        let cfg = crate::test_helpers::make_test_config_with_severity(
            "if_none_match_etag_syntax",
            "warn",
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = IfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("if-none-match", bad);
        tx.request.headers = hm;

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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "if_none_match_etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn empty_header_value_reports_violation() {
        let rule = IfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("empty or contains only whitespace"));
    }

    #[test]
    fn comma_only_header_reports_violation() {
        let rule = IfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", ",")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_header_fields_merged_and_valid() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = IfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("if-none-match", HeaderValue::from_static("W/\"a\""));
        hm.append("if-none-match", HeaderValue::from_static("\"b\""));
        tx.request.headers = hm;

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
    fn multiple_header_fields_one_invalid_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = IfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("if-none-match", HeaderValue::from_static("W/\"a\""));
        hm.append("if-none-match", HeaderValue::from_static("b"));
        tx.request.headers = hm;

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
    fn id_and_scope_are_expected() {
        let r = IfNoneMatchEtagSyntax;
        assert_eq!(r.id(), "if_none_match_etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }

    /// **`"*" / #entity-tag` is an alternation.** The `*` is the whole field
    /// value, and it was asked of each member instead -- so a list holding one
    /// derived from neither alternative and passed. The other three cases are
    /// what the extraction found beside it: the walk is quote-aware now, an
    /// empty member is named as one, and § 5.2 decides the alternation on the
    /// value the field lines make rather than on any one of them.
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
    #[case(&[&b"\"a\", , \"b\""[..]], Some("empty list element"))]
    #[case(&[&b""[..]], Some("empty or contains only whitespace"))]
    fn the_wildcard_is_the_whole_field_value_and_not_a_member(
        #[case] lines: &[&[u8]],
        #[case] expected: Option<&str>,
    ) {
        use hyper::header::{HeaderName, HeaderValue};
        let rule = IfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        for line in lines {
            tx.request.headers.append(
                HeaderName::from_static("if-none-match"),
                HeaderValue::from_bytes(line).expect("a test If-None-Match value"),
            );
        }
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        match expected {
            None => assert!(v.is_none(), "expected silence for {lines:?}: {v:?}"),
            Some(sub) => {
                let v = v.unwrap_or_else(|| panic!("expected a violation for {lines:?}"));
                assert!(v.message.contains(sub), "{}", v.message);
            }
        }
    }
}
