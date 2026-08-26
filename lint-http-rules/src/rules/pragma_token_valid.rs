// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Pragma` header directives must follow `directive = token ["=" ( token / quoted-string )]`
/// and be syntactically valid. This rule flags invalid tokens, malformed quoted-strings,
/// non-UTF8 header values, and empty list members.
///
/// RFC 9111 §5.4 defines `Pragma` (an HTTP/1.0 request field) but *deprecates* it and no
/// longer specifies a grammar for it; the `token ["=" (token / quoted-string)]` directive
/// shape is the historical one from the obsoleted RFC 7234 §5.4. The leaf syntax this rule
/// actually enforces — the `#`-list construct, `token`, and `quoted-string` — is current
/// RFC 9110 §5.6 machinery, applied here as a well-formedness check for a deprecated field.
pub struct PragmaTokenValid;

impl Rule for PragmaTokenValid {
    fn id(&self) -> &'static str {
        "pragma_token_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // Validate request headers
        // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
        for header_val in tx.request.headers.get_all("pragma").iter() {
            if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                // An entirely empty Pragma value is a legal zero-element list, distinct from
                // an empty element *within* a list (flagged in check_pragma_value). Skip it.
                if v.is_empty() {
                    continue;
                }
                if let Some(msg) = check_pragma_value(v) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: ctx.severity,
                        message: format!("Invalid Pragma header in request: {}", msg),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: "Pragma header contains non-UTF8 value".into(),
                });
            }
        }

        // Validate response headers too. Pragma is a deprecated request field whose meaning in
        // responses was never specified (§5.4 Note), so this is a pure well-formedness check for
        // a field that should not appear here at all.
        // cite(RFC 9111 § 5.4): "As a result, this specification deprecates Pragma."
        if let Some(resp) = &tx.response {
            for header_val in resp.headers.get_all("pragma").iter() {
                if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                    // An entirely empty Pragma value is a legal zero-element list, distinct from
                    // an empty element *within* a list (flagged in check_pragma_value). Skip it.
                    if v.is_empty() {
                        continue;
                    }
                    if let Some(msg) = check_pragma_value(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: ctx.severity,
                            message: format!("Invalid Pragma header in response: {}", msg),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: ctx.severity,
                        message: "Pragma header contains non-UTF8 value".into(),
                    });
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "The `Pragma` header directives must follow directive syntax: a `token` optionally followed by `=token` or `=\"quoted-string\"`.\nThis rule flags malformed directives, invalid token characters, empty members, and non-UTF8 header values.\n`Pragma` is deprecated by RFC 9111 §5.4, which no longer specifies its grammar; this validates the historical HTTP/1.0 directive syntax (originally RFC 7234 §5.4)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9111",
            section: Some("5.4"),
            url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4",
            note: "Pragma",
        }]
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

fn check_pragma_value(s: &str) -> Option<String> {
    // The `token ["=" (token / quoted-string)]` directive shape is RFC 7234 §5.4's historical
    // `extension-pragma` (dropped by RFC 9111). The pieces enforced below — the `#`-list split,
    // the empty-element rule, `token`, and `quoted-string` — are all current RFC 9110 §5.6.
    for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
        // An empty element *within* the list (e.g. `no-cache,,foo` or a trailing comma) is
        // forbidden, unlike the empty whole value skipped by the callers above.
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if member.is_empty() {
            return Some("Empty directive in Pragma header".into());
        }

        let mut kv = member.splitn(2, '=');
        // A directive name is a `token`, which is `1*tchar` — at least one character, so an empty
        // name (as in `=abc`) is invalid. `find_invalid_token_char` below owns the tchar set.
        // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
        let name = kv.next().unwrap().trim();
        if name.is_empty() {
            return Some(format!(
                "Empty directive name in Pragma member: '{}'",
                member
            ));
        }

        // Grammar owned by the helper (RFC 9110 §5.6.2 `token`).
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(format!(
                "Directive name contains invalid character: '{}'",
                c
            ));
        }

        if let Some(vpart) = kv.next() {
            let vpart = vpart.trim();
            // The `( token / quoted-string )` alternation is read by the shared
            // helper that owns it; what stays here is what this field says about
            // each answer.
            match crate::helpers::headers::token_or_quoted_string(vpart) {
                Ok(_) => {}
                // A bare `directive=` (the `=` present with no value) is more permissive than the
                // grammar, which requires a `token` or `quoted-string` after `=`; accepted as a
                // deliberate tolerance for this deprecated field. Written as an
                // arm rather than as a pre-check, because it is a verdict this
                // rule reaches and not a step of reading the value.
                Err(crate::helpers::headers::WordDefect::Empty) => continue,
                Err(crate::helpers::headers::WordDefect::NotQuotedString(e)) => {
                    return Some(format!("Invalid quoted-string in directive value: {}", e));
                }
                Err(crate::helpers::headers::WordDefect::NotToken(c)) => {
                    return Some(format!(
                        "Directive value contains invalid character: '{}'",
                        c
                    ));
                }
            }
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PragmaTokenValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
            trailers: None,
        });
        tx
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
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
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
        assert!(v.is_some());
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
    fn response_non_utf8_value_is_violation() -> anyhow::Result<()> {
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
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("pragma_token_valid".into(), toml::Value::Table(table));
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = PragmaTokenValid;
        assert_eq!(r.id(), "pragma_token_valid");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }
}
