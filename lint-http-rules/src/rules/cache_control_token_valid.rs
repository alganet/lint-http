// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{cache_directive_member, LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CacheControlTokenValid;

/// The same eight defects `pragma_token_valid` declares, and for the same
/// reason: this rule measures `cache-directive = token [ "=" ( token /
/// quoted-string ) ]` and every part of that is RFC 9110 § 5.6 machinery the
/// field borrows.
///
/// **The two rules used to write two of these findings out in identical words.**
/// "Invalid quoted-string in directive value" and "Directive value contains
/// invalid character" appear character for character in both files — one of the
/// fourteen duplicate templates this campaign's measurement counted — because
/// each rule had to word a finding about a production neither of them owns.
/// They are one id apiece now, which is the state Phase 5's dedup can act on and
/// a rule-shaped catalogue could not reach.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_EMPTY,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2",
    note: "Cache-Control directives and general directive syntax",
};

impl CacheControlTokenValid {
    /// The first defect in one message's `Cache-Control` field, if it has one.
    ///
    /// Read over the whole section and as octets. `Cache-Control =
    /// #cache-directive` makes the field lines of a section one list, and a
    /// directive name holding an octet outside visible US-ASCII is a `token`
    /// defect rather than a fact about the field's encoding — which is what
    /// reading line by line through the string reader made it. Where the
    /// members come from, and which of them the grammar's `#element` even
    /// admits, is [`crate::helpers::cache_control`]'s answer.
    fn defect(
        &self,
        headers: &hyper::HeaderMap,
        side: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let value =
            crate::helpers::headers::combined_field_value_as_written(headers, "cache-control")?;
        for member in crate::helpers::cache_control::members_of(&value) {
            if let Some((def, message)) = member_defect(member) {
                return Some(ctx.report_with(
                    def,
                    format!("Invalid Cache-Control header in {}: {}", side, message),
                ));
            }
        }
        None
    }
}

impl RuleMeta for CacheControlTokenValid {
    fn id(&self) -> &'static str {
        "cache_control_token_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Cache-Control` directive names and unquoted values follow the `token` grammar. Values that are quoted-strings are validated as quoted strings. An empty directive member within the list (for example a stray or trailing comma) is flagged; an entirely empty header value is not, because `Cache-Control` is a comma-separated list and an empty value is a legal zero-element list."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_2,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
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
                snippet: "Cache-Control: max-age=3600\nCache-Control: no-cache\nCache-Control: private=\"Set-Cookie, X-Foo\"\nCache-Control: public, max-age=60",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Cache-Control: =abc\nCache-Control: ma x-age=1\nCache-Control: private=Set Cookie\nCache-Control: private=bad@val",
            },
        ]
    }
}

impl Rule for CacheControlTokenValid {
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
        //
        // Both sides of the exchange carry this field and are read the same way;
        // only the word in the finding differs.
        // cite(RFC 9111 § 5.2): "The "Cache-Control" header field is used to list directives for caches along the request/response chain."
        let finding = || -> Option<Violation> {
            self.defect(&tx.request.headers, "request", ctx)
                .or_else(|| {
                    let resp = tx.response.as_ref()?;
                    self.defect(&resp.headers, "response", ctx)
                })
        };
        Vec::from_iter(finding())
    }
}

/// What is wrong with one `cache-directive`, if anything.
///
/// The name is read by the shared strict reader; what stays here is this rule's
/// own question, which is about the value's *shape* rather than about what any
/// particular directive means by it.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
fn member_defect(member: &str) -> Option<(&'static ViolationDef, String)> {
    let directive = match crate::helpers::cache_control::read_member(member) {
        Ok(directive) => directive,
        Err(defect) => return Some((cache_directive_member(defect), defect.message())),
    };
    let argument = directive.argument?;

    // The `( token / quoted-string )` alternation is read by the shared helper
    // that owns it; what stays here is what this field says about each answer.
    match crate::helpers::word::token_or_quoted_string(argument) {
        Ok(_) => None,
        // Leniency, recorded rather than changed: `foo=` does not match the
        // grammar above — once "=" is present the optional group requires a
        // token (`1*tchar`) or a quoted-string, neither of which can be empty.
        // The rule accepts it anyway, so it under-reports this one shape. That
        // is the safe direction for a linter, and tightening it would be a
        // behavior change. (`foo=""` is genuinely valid: quoted-string permits
        // empty content.)
        Err(crate::helpers::word::WordDefect::Empty) => None,
        Err(crate::helpers::word::WordDefect::NotQuotedString(defect)) => Some((
            quoted_string_defect(defect),
            format!(
                "Invalid quoted-string in directive value: {}",
                defect.message(argument)
            ),
        )),
        Err(crate::helpers::word::WordDefect::NotToken(c)) => Some((
            token_character(c),
            format!("Directive value contains invalid character: '{}'", c),
        )),
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlTokenValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", val)]);
        tx
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("cache-control", val)]),
            body_length: None,
            trailers: None,
        });
        tx
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("no-cache", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("public, max-age=60", false)]
    #[case("", false)] // empty value = legal zero-element list
    #[case("=abc", true)]
    #[case("ma x-age=1", true)]
    #[case("private=Set Cookie", true)]
    #[case("private=bad@val", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let tx = make_req(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("no-cache", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("public, max-age=60", false)]
    #[case("", false)] // empty value = legal zero-element list
    #[case("=abc", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let tx = make_resp(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[test]
    fn an_obs_text_octet_in_a_directive_name_is_a_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.request.headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in request: Directive name contains invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("cache-control", "no-cache"),
            ("cache-control", "max-age=60"),
        ]);
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
    fn response_multiple_headers_merged_are_valid() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("cache-control", "no-cache"),
            ("cache-control", "max-age=60"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    /// The pair of rules that used to write the same sentence twice now report
    /// the same id, and the ids are the productions': the list, the token, the
    /// quoted-string. Asserted here against the *other* rule's verdict on the
    /// equivalent value, which is the whole claim in one assertion — two fields,
    /// two rules, one name for one mistake.
    #[test]
    fn the_directive_and_the_pragma_rule_report_one_id_for_one_mistake() {
        let judge = |rule: &dyn crate::rules::Rule, field: &str, value: &str| -> String {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);
            crate::test_helpers::run_rule(
                rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .unwrap_or_else(|| panic!("{field}: {value}"))
            .violation
        };

        for (value, id) in [
            ("no-cache,,foo", "list_member_empty"),
            ("=abc", "token_empty"),
            ("foo=bad@value", "token_character_forbidden"),
            ("foo=\"unterminated", "quoted_string_delimiter_missing"),
        ] {
            assert_eq!(
                judge(&CacheControlTokenValid, "cache-control", value),
                id,
                "{value}"
            );
            assert_eq!(
                judge(
                    &crate::rules::pragma_token_valid::PragmaTokenValid,
                    "pragma",
                    value
                ),
                id,
                "{value}"
            );
        }
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let tx = make_req("foo=\"bar\"x");
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
    fn quoted_value_unterminated_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let tx = make_req("foo=\"unterminated");
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
    fn empty_directive_value_is_accepted() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let tx = make_req("foo=");
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
    fn a_responses_obs_text_octet_is_the_same_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in response: Directive name contains invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", ",max-age=1")]);
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
    fn scope_is_both() {
        let rule = CacheControlTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CacheControlTokenValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "cache_control_token_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }
}
