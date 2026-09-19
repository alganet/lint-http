// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN, QUOTED_STRING_DELIMITER_MISSING,
    QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

/// Everything this rule reports, and none of it is `Pragma`'s.
///
/// The field's own document deprecates it and states no grammar at all — RFC
/// 9111 § 5.4 names it and stops — so what is left to measure is machinery this
/// rule *borrows*: the `#` list construct, `token`, and `quoted-string`, each
/// current RFC 9110 § 5.6 and each already a subject. A deprecated field with
/// no grammar of its own turns out to be the cleanest possible demonstration
/// that the defect belongs to the production and not to the field.
///
/// `cache_control_token_valid` writes two of these messages out in the same
/// words, which is one of the fourteen duplicate templates the campaign's
/// measurement found; when it converts, the two rules will report one id apiece
/// rather than two identical sentences under two rule names.
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

/// `Pragma` header directives must follow `directive = token ["=" ( token / quoted-string )]`
/// and be syntactically valid. This rule flags invalid tokens, malformed quoted-strings,
/// empty list members, and directive names holding an octet no `tchar` admits.
///
/// RFC 9111 §5.4 defines `Pragma` (an HTTP/1.0 request field) but *deprecates* it and no
/// longer specifies a grammar for it; the `token ["=" (token / quoted-string)]` directive
/// shape is the historical one from the obsoleted RFC 7234 §5.4. The leaf syntax this rule
/// actually enforces — the `#`-list construct, `token`, and `quoted-string` — is current
/// RFC 9110 §5.6 machinery, applied here as a well-formedness check for a deprecated field.
pub struct PragmaTokenValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4",
    note: "Pragma",
};

impl RuleMeta for PragmaTokenValid {
    fn id(&self) -> &'static str {
        "pragma_token_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "The `Pragma` header directives must follow directive syntax: a `token` optionally followed by `=token` or `=\"quoted-string\"`.\nThis rule flags malformed directives, invalid token characters and empty members. The value is read as octets over the whole field section, so an octet outside visible US-ASCII in a directive name is reported as the character the production does not admit — not as a verdict about the field's encoding, which is what the reader this replaces made of it.\n`Pragma` is deprecated by RFC 9111 §5.4, which no longer specifies its grammar; this validates the historical HTTP/1.0 directive syntax (originally RFC 7234 §5.4)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_4,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **`Pragma` was defined for a request and is seen in both halves**, so
    /// the field's own grammar is read out of each and the malformed directive
    /// belongs to the peer that wrote it. Whether a *response* should carry the
    /// field at all is `cache_control_and_pragma_consistent`'s question, asked
    /// there and answered the same way.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nPragma: no-cache\nPragma: no-cache, foo=bar\nPragma: token=\"quoted,comma\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nPragma: not a token",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nPragma: =abc",
            },
        ]
    }
}

impl Rule for PragmaTokenValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per directive, and both sections read. A defect in the
        // request's `Pragma` used to end the body before the response's was
        // looked at.
        let findings = || -> Vec<Violation> {
            let mut out = Vec::new();
            // Validate request headers
            // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
            // Read as octets, and over the section: the historical
            // production is a `#`-list, so the field lines of one section
            // are one list, and an octet outside visible US-ASCII in a
            // directive name is the `token`'s defect rather than a verdict
            // about the field's encoding.
            if let Some(v) = crate::helpers::headers::combined_field_value_as_written(
                &tx.request.headers,
                "pragma",
            ) {
                // An entirely empty Pragma value is a legal zero-element list, distinct from
                // an empty element *within* a list (flagged in check_pragma_value). Skip it.
                let v = v.trim();
                if !v.is_empty() {
                    out.extend(check_pragma_value(v).into_iter().map(|(def, msg)| {
                        ctx.by_client()
                            .report_with(def, format!("Invalid Pragma header in request: {}", msg))
                    }));
                }
            }

            // Validate response headers too. Pragma is a deprecated request field whose meaning in
            // responses was never specified (§5.4 Note), so this is a pure well-formedness check for
            // a field that should not appear here at all.
            // cite(RFC 9111 § 5.4): "As a result, this specification deprecates Pragma."
            if let Some(resp) = &tx.response {
                if let Some(v) = crate::helpers::headers::combined_field_value_as_written(
                    &resp.headers,
                    "pragma",
                ) {
                    let v = v.trim();
                    if !v.is_empty() {
                        out.extend(check_pragma_value(v).into_iter().map(|(def, msg)| {
                            ctx.by_server().report_with(
                                def,
                                format!("Invalid Pragma header in response: {}", msg),
                            )
                        }));
                    }
                }
            }

            out
        };
        findings()
    }
}

fn check_pragma_value(s: &str) -> Vec<(&'static ViolationDef, String)> {
    // The `token ["=" (token / quoted-string)]` directive shape is RFC 7234 §5.4's historical
    // `extension-pragma` (dropped by RFC 9111). The pieces enforced below — the `#`-list split,
    // the empty-element rule, `token`, and `quoted-string` — are all current RFC 9110 §5.6.
    // One finding per directive. The historical production is a `#`-list and
    // each position holds a directive the sender wrote on its own terms, so a
    // value naming two the recipient cannot read is two directives to correct --
    // and a walk that returned at the first named one.
    //
    // The gap stays one finding for the value: § 5.6.1.1 forbids generating an
    // empty *element*, and a value written with three of them is one list with
    // gaps in it.
    let mut found = Vec::new();
    let mut saw_an_empty_member = false;
    'member: for member in crate::helpers::list::split_commas_respecting_quotes(s) {
        // An empty element *within* the list (e.g. `no-cache,,foo` or a trailing comma) is
        // forbidden, unlike the empty whole value skipped by the callers above.
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if member.is_empty() {
            saw_an_empty_member = true;
            continue;
        }

        let mut kv = member.splitn(2, '=');
        // A directive name is a `token`, which is `1*tchar` — at least one character, so an empty
        // name (as in `=abc`) is invalid. `find_invalid_token_char` below owns the tchar set.
        // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
        let name = kv.next().unwrap().trim();
        if name.is_empty() {
            found.push((
                &TOKEN_EMPTY,
                format!("Empty directive name in Pragma member: '{}'", member),
            ));
            continue 'member;
        }

        // Grammar owned by the helper (RFC 9110 §5.6.2 `token`).
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            found.push((
                token_character(c),
                format!(
                    "Directive name contains invalid character: {}",
                    crate::helpers::shown::describe_char(c)
                ),
            ));
            continue 'member;
        }

        if let Some(vpart) = kv.next() {
            let vpart = vpart.trim();
            // The `( token / quoted-string )` alternation is read by the shared
            // helper that owns it; what stays here is what this field says about
            // each answer.
            match crate::helpers::word::token_or_quoted_string(vpart) {
                Ok(_) => {}
                // A bare `directive=` (the `=` present with no value) is more permissive than the
                // grammar, which requires a `token` or `quoted-string` after `=`; accepted as a
                // deliberate tolerance for this deprecated field. Written as an
                // arm rather than as a pre-check, because it is a verdict this
                // rule reaches and not a step of reading the value.
                //
                // It is also the one answer the catalogue leaves open: the
                // alternation's mapping returns nothing for an empty value,
                // because the verdict is each field's, and this field's is
                // written here.
                Err(crate::helpers::word::WordDefect::Empty) => continue,
                Err(crate::helpers::word::WordDefect::NotQuotedString(defect)) => {
                    found.push((
                        crate::violations::quoted_string::quoted_string_defect(defect),
                        format!(
                            "Invalid quoted-string in directive value: {}",
                            defect.message(vpart)
                        ),
                    ));
                    continue 'member;
                }
                Err(crate::helpers::word::WordDefect::NotToken(c)) => {
                    found.push((
                        token_character(c),
                        format!("Directive value contains invalid character: '{}'", c),
                    ));
                    continue 'member;
                }
            }
        }
    }

    if saw_an_empty_member {
        found.push((
            &LIST_MEMBER_EMPTY,
            "Empty directive in Pragma header".into(),
        ));
    }

    found
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PragmaTokenValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// **Every directive the sender wrote is answered.** The historical
    /// production is a `#`-list and each position holds a directive written on
    /// its own terms, so two the recipient cannot read are two to correct — and
    /// the gap beside them is the list's own defect, counted once.
    #[test]
    fn every_defective_directive_is_reported_beside_the_gap() {
        let rule = PragmaTokenValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["pragma_token_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "pragma",
            "n@cache,,foo=\",,no-cache",
        )]);
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<_> = found.iter().map(|v| v.violation.as_str()).collect();
        assert!(ids.contains(&"token_character_forbidden"), "{ids:?}");
        assert!(ids.contains(&"quoted_string_delimiter_missing"), "{ids:?}");
        assert_eq!(
            ids.iter().filter(|i| **i == "list_member_empty").count(),
            1,
            "the gaps are one list defect: {ids:?}"
        );
    }

    fn make_req(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("pragma", val)]);
        tx
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("pragma", val)]),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        tx
    }

    /// Every defect this deprecated field reports is a borrowed one, and the
    /// ids say which document it was borrowed from: the list construct, the
    /// token and the quoted-string, all RFC 9110 § 5.6. `Pragma`'s own document
    /// states no grammar, so there was never anything else for these findings
    /// to be named after.
    ///
    /// **Four of the five are `error` and the `@` a sender typed is `warn`**,
    /// which one rule severity could not express either way. The four are
    /// values no production generates; the fifth is
    /// `token_character_forbidden`, which the catalogue keeps a level below its
    /// `_whitespace_or_control_forbidden` twin because an octet nobody typed
    /// and a character somebody chose are not the same report.
    #[test]
    fn every_defect_is_the_borrowed_productions_and_not_the_fields() {
        for (value, id, severity) in [
            (
                "no-cache,,foo",
                "list_member_empty",
                crate::lint::Severity::Error,
            ),
            ("=abc", "token_empty", crate::lint::Severity::Error),
            (
                "bad token",
                "token_whitespace_or_control_forbidden",
                crate::lint::Severity::Error,
            ),
            (
                "foo=bad@value",
                "token_character_forbidden",
                crate::lint::Severity::Warn,
            ),
            (
                "foo=\"unterminated",
                "quoted_string_delimiter_missing",
                crate::lint::Severity::Error,
            ),
        ] {
            let found = crate::test_helpers::run_rule(
                &PragmaTokenValid,
                &make_req(value),
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&["pragma_token_valid"]),
            )
            .unwrap_or_else(|| panic!("{value:?}"));
            assert_eq!(found.violation, id, "{value:?}");
            assert_eq!(found.severity, severity, "{value:?}");
        }
    }

    #[rstest]
    #[case("no-cache", false)]
    #[case("no-cache, foo=bar", false)]
    #[case("no-cache, token=\"quoted,comma\"", false)]
    // An entirely empty Pragma value is a legal zero-element list, not a violation.
    #[case("", false)]
    #[case("=abc", true)]
    #[case("bad token", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = PragmaTokenValid;
        let tx = make_req(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}', got: {:?}",
                value,
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[rstest]
    #[case("no-cache", false)]
    #[case("no-cache, foo=bar", false)]
    // An entirely empty Pragma value is a legal zero-element list, not a violation.
    #[case("", false)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = PragmaTokenValid;
        let tx = make_resp(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}', got: {:?}",
                value,
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn trailing_comma_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("no-cache,");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn directive_name_invalid_char_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("n@me=1");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn token_value_invalid_char_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("foo=ba@d");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_value_unterminated_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("foo=\"unterminated");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_directive_value_is_accepted() {
        let rule = PragmaTokenValid;
        let tx = make_req("foo=");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn list_with_invalid_middle_member_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("no-cache, bad@name=1, max-age=0");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn an_obs_text_octet_in_a_directive_name_is_a_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = PragmaTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("pragma", bad);
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
            "Invalid Pragma header in request: Directive name contains invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_violation() {
        let rule = PragmaTokenValid;
        let tx = make_req("foo=\"bar\"x");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn a_responses_obs_text_octet_is_the_same_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = PragmaTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = hyper::HeaderMap::new();
        hm.insert("pragma", bad);
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
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Pragma header in response: Directive name contains invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn empty_directive_value_in_response_is_accepted() {
        let rule = PragmaTokenValid;
        let tx = make_resp("foo=");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_merged_are_checked() {
        let rule = PragmaTokenValid;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("pragma", "no-cache"),
            ("pragma", "foo=bar"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = PragmaTokenValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("pragma_token_valid".into(), toml::Value::Table(table));
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = PragmaTokenValid;
        assert_eq!(r.id(), "pragma_token_valid");
        assert!(!r.needs_response());
    }
}
