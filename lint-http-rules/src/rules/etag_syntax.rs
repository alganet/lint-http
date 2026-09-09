// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::etag::{
    entity_tag_defect, ETAG_CHARACTER_FORBIDDEN, ETAG_DELIMITER_MISSING,
    ETAG_WEAK_INDICATOR_INVALID, RFC_9110_8_8_3,
};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::ViolationDef;

/// The production's three defects, which is everything this rule says about a
/// value that is not an entity-tag.
///
/// `ETag = entity-tag` and § 8.8.3 adds nothing to the production, so the ids
/// are the production's and the two conditional-field rules answer with the
/// same three. What stays this rule's own is what an `ETag` *field* may be: a
/// `*` is not a tag but is the shape a server copies from the conditional
/// fields, and more than one field line is a statement about the message.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &ETAG_WEAK_INDICATOR_INVALID,
    &ETAG_DELIMITER_MISSING,
    &ETAG_CHARACTER_FORBIDDEN,
];

/// Validate `ETag` header values: must be a single entity-tag (strong or weak
/// quoted-string) per RFC 9110 §8.8.3. Also flags a repeated field line.
///
/// Both specification references this rule declares now live beside the defs
/// they answer for — the entity-tag grammar in `violations/etag.rs` and § 5.3's
/// field order in `violations/field.rs` — which is why no `SpecRef` is written
/// here.
pub struct EtagSyntax;

impl RuleMeta for EtagSyntax {
    fn id(&self) -> &'static str {
        "etag_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "Validate that the `ETag` response header contains a single, syntactically valid entity-tag (strong or weak) as defined by RFC 9110. This rule flags non-UTF-8 header values, the use of the special `*` value (which is only meaningful in conditional request headers), and the presence of multiple `ETag` header fields."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_8_3, RFC_9110_5_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(strong ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(weak ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: W/\"67ab43\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`*` used in response)"),
                snippet: "HTTP/1.1 200 OK\nETag: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing quotes)"),
                snippet: "HTTP/1.1 200 OK\nETag: abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"a\"\nETag: \"b\"",
            },
        ]
    }
}

impl Rule for EtagSyntax {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            // ETag is a response field, which is why this rule is Server-scoped and only
            // inspects the response.
            // cite(RFC 9110 § 8.8.3): "The "ETag" field in a response provides the current entity tag for the selected representation, as determined at the conclusion of handling the request."
            let Some(resp) = &tx.response else {
                return None;
            };

            let mut count = 0usize;
            for hv in resp.headers.get_all("etag").iter() {
                count += 1;
                // Read as octets. `ETag = entity-tag` is one value rather than
                // a list, so the field line is the value; and `etagc` stops at
                // %x7E except for `obs-text`, so an octet outside visible
                // US-ASCII is measured against the production like any other
                // rather than folded into a verdict about the field's
                // encoding. The two conditional fields that quote this value
                // back have read it this way since their own conversion.
                let s = crate::helpers::headers::field_line_as_written(hv);

                let t = s.trim();
                // The `*` kept its own branch, and the reason changed. It stood here
                // because `check_entity_tag` admitted a `*` -- which no
                // `entity-tag` generates, and the helper refuses now -- so the branch
                // is no longer a correction of the helper. It stays because this
                // finding is worth more than the helper's: `*` is the one non-tag an
                // `ETag` plausibly holds, written by a server copying the shape of
                // the conditional fields that do take it.
                // cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
                if t == "*" {
                    return Some(self.cited(&RFC_9110_8_8_3, ctx.severity, "ETag header value '*' is invalid for responses; ETag must be an entity-tag"
                                .into()));
                }

                // The entity-tag grammar itself (§8.8.3) is owned by `check_entity_tag`.
                if let Err(defect) = crate::helpers::validator::check_entity_tag(t) {
                    return Some(ctx.report_with(
                        entity_tag_defect(defect),
                        format!("ETag header invalid: {}", defect.message()),
                    ));
                }
            }

            // `ETag = entity-tag` is a single value, not a list (`#entity-tag`), so ETag is
            // not a field whose lines may be recombined as a comma-separated list — the §5.3
            // exception does not apply, and a sender must emit at most one ETag field line.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(ctx.report_with(&FIELD_LINE_DUPLICATED, format!(
                        "Multiple ETag header fields present ({}); ETag must be a single entity-tag",
                        count
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &EtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One production, three fields: an `ETag` a server sends and the two
    /// conditional lists a client sends back draw the same id for the same
    /// value, out of rules that share no code and read opposite directions of
    /// the exchange.
    #[rstest]
    #[case("abc", "etag_delimiter_missing")]
    #[case("w/\"abc\"", "etag_weak_indicator_invalid")]
    #[case("\"a\"b\"", "etag_character_forbidden")]
    fn a_validator_is_the_same_defect_in_both_directions(#[case] value: &str, #[case] id: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("etag", value)]);
        let found = crate::test_helpers::run_rule(
            &EtagSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity("etag_syntax", "warn"),
        )
        .expect("a finding");
        assert_eq!(found.violation, id, "{value}");

        for (rule, field) in [
            (
                &super::super::if_match_etag_syntax::IfMatchEtagSyntax as &dyn crate::rules::Rule,
                "if-match",
            ),
            (
                &super::super::if_none_match_etag_syntax::IfNoneMatchEtagSyntax,
                "if-none-match",
            ),
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_headers(&[(field, value)]);
            let found = crate::test_helpers::run_rule(
                rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_severity(rule.id(), "warn"),
            )
            .expect("a finding");
            assert_eq!(found.violation, id, "{field}: {value}");
        }
    }

    #[rstest]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("abc"), true)]
    #[case(None, false)]
    fn etag_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = EtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = value {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[("etag", v)]),

                body_length: None,
                trailers: None,
            });
        }

        let cfg = crate::test_helpers::make_test_config_with_severity(rule.id(), "warn");

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for value={:?}", value);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for value={:?}: {:?}",
                value,
                v
            );
        }
    }

    #[test]
    /// An octet outside visible US-ASCII is measured against `etagc`, which
    /// admits `obs-text` and refuses the rest — not folded into a verdict
    /// about the field's encoding, which is what the reader this replaces
    /// reported.
    fn an_obs_text_octet_is_measured_against_the_production() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = EtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("etag", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "etag_delimiter_missing");
        Ok(())
    }

    #[test]
    fn multiple_etag_headers_reported() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = EtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("etag", HeaderValue::from_static("\"a\""));
        hm.append("etag", HeaderValue::from_static("\"b\""));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = EtagSyntax;
        assert_eq!(r.id(), "etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }
}
