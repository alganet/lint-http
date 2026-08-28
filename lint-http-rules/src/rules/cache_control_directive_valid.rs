// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct CacheControlDirectiveValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2",
    note: "Cache-Control directives and general directive syntax",
};

impl CacheControlDirectiveValid {
    /// The first defect in one message's `Cache-Control` field, if it has one.
    ///
    /// Read line by line rather than over the whole section, because an
    /// unreadable line is one of the findings and the field line is what that
    /// finding is about. Where the members come from, and which of them the
    /// grammar's `#element` even admits, is
    /// [`crate::helpers::cache_control`]'s answer.
    fn defect(
        &self,
        headers: &hyper::HeaderMap,
        side: &str,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        for line in headers.get_all("cache-control").iter() {
            let Ok(line) = line.to_str() else {
                return Some(self.violation(
                    severity,
                    "Cache-Control header contains non-UTF8 value".into(),
                ));
            };
            for member in crate::helpers::cache_control::members_of(line) {
                if let Some(message) = member_defect(member) {
                    return Some(self.violation(
                        severity,
                        format!("Invalid Cache-Control header in {}: {}", side, message),
                    ));
                }
            }
        }
        None
    }
}

impl Rule for CacheControlDirectiveValid {
    fn id(&self) -> &'static str {
        "cache_control_directive_valid"
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
        //
        // Both sides of the exchange carry this field and are read the same way;
        // only the word in the finding differs.
        // cite(RFC 9111 § 5.2): "The "Cache-Control" header field is used to list directives for caches along the request/response chain."
        let finding = || -> Option<Violation> {
            self.defect(&tx.request.headers, "request", ctx.severity)
                .or_else(|| {
                    let resp = tx.response.as_ref()?;
                    self.defect(&resp.headers, "response", ctx.severity)
                })
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate `Cache-Control` directive names and argument formats for common correctness issues. This rule enforces directive-specific semantics such as:\n\n- `max-age` and `s-maxage` must have non-negative integer values (delta-seconds).\n- `private` and `no-cache` when carrying a field-name-list must provide a comma-separated list of field-names (tokens) either as an unquoted list or inside a quoted-string.\n- Unquoted directive values must follow the `token` grammar and quoted values must be valid `quoted-string`s.\n\nThis rule complements `cache_control_token_valid` which enforces general token/quoted-string syntax."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Cache-Control: max-age=3600\nCache-Control: s-maxage=0, public\nCache-Control: private=\"Set-Cookie, X-Foo\"\nCache-Control: private=Foo,bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Cache-Control: max-age=abc     # non-numeric max-age\nCache-Control: max-age=-1      # negative values not allowed\nCache-Control: s-maxage=1.5    # fractional values invalid\nCache-Control: private=Set Cookie  # space in token\nCache-Control: private=\"Set Cookie\" # quoted content contains space-separated token",
            },
        ]
    }
}

/// What is wrong with one `cache-directive`, if anything.
///
/// The name is read by the shared strict reader, which owns the three defects
/// the two Cache-Control syntax rules report identically. What this rule adds is
/// the part that is its own: what each *named* directive's argument may say.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
fn member_defect(member: &str) -> Option<String> {
    let directive = match crate::helpers::cache_control::read_member(member) {
        Ok(directive) => directive,
        Err(message) => return Some(message),
    };
    let name = directive.name;
    // An empty argument is accepted for directives that take one; the `=` with
    // nothing after it is the leniency recorded in the token rule beside this.
    let argument = directive.argument.filter(|a| !a.is_empty())?;

    match name.to_ascii_lowercase().as_str() {
        "max-age" | "s-maxage" => {
            // Both take a delta-seconds argument, which is why a sign, a
            // decimal point or any non-digit is rejected here.
            // cite(RFC 9111 § 1.2.2): "The delta-seconds rule specifies a non-negative integer, representing time in seconds."
            if let Some(c) = crate::helpers::token::find_invalid_token_char(argument) {
                // If it contains non-token chars it's invalid (no quotes allowed here)
                return Some(format!(
                    "{} value contains invalid character: '{}'",
                    name, c
                ));
            }
            if argument.chars().any(|ch| !ch.is_ascii_digit()) {
                return Some(format!("{} must be a non-negative integer", name));
            }
            // A digit run too large for any particular integer type is still
            // syntactically valid `1*DIGIT`, and the spec says what to do about
            // it — clamp, not reject — so there is nothing here to report. The
            // value's magnitude is the recipient's problem, not the sender's.
            // cite(RFC 9111 § 1.2.2): "If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648"
            // cite(RFC 9111 § 1.2.2): "or the greatest positive integer it can conveniently represent."
            None
        }
        // Both take the same optional argument: a `#field-name` list, which is
        // what this branch validates (as a quoted-string or, leniently, as a
        // bare comma-separated list). The sentence below is stated for private;
        // no-cache's qualified form (§5.2.2.4) has the same shape.
        // cite(RFC 9111 § 5.2.2.7): "If a qualified private response directive is present, with an argument that lists one or more field names"
        "private" | "no-cache" => field_name_list_defect(name, argument),
        _ => {
            // For other directives, accept token or quoted-string and ensure token syntax if unquoted
            if argument.starts_with('"') {
                if let Err(e) = crate::helpers::headers::validate_quoted_string(argument) {
                    return Some(format!(
                        "Invalid quoted-string in directive {} value: {}",
                        name, e
                    ));
                }
                return None;
            }
            crate::helpers::token::find_invalid_token_char(argument).map(|c| {
                format!(
                    "Directive {} value contains invalid character: '{}'",
                    name, c
                )
            })
        }
    }
}

/// The `#field-name` argument `private` and `no-cache` share, quoted or bare.
///
/// The two spellings ask the same question of each name, which is why the walk
/// below is written once over whichever list the argument turned out to be.
fn field_name_list_defect(name: &str, argument: &str) -> Option<String> {
    let list = if argument.starts_with('"') {
        match crate::helpers::headers::unescape_quoted_string(argument) {
            Ok(inner) => inner,
            Err(e) => return Some(format!("Invalid quoted-string in {} value: {}", name, e)),
        }
    } else {
        // unquoted: allow single token or comma-separated tokens
        argument.to_string()
    };

    for field in list.split(',') {
        let field = field.trim();
        if field.is_empty() {
            return Some(format!("Empty field-name in {} value", name));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(field) {
            return Some(format!(
                "{} includes invalid field-name character: '{}'",
                name, c
            ));
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlDirectiveValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(val: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_headers(&[("cache-control", val)])
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(200, &[("cache-control", val)])
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=Foo", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    #[case("no-cache=field1,field2", false)]
    #[case("no-cache=\"field1, field2\"", false)]
    #[case("public, max-age=60", false)]
    #[case("foo=bar", false)]
    #[case("max-age=abc", true)]
    #[case("max-age=-1", true)]
    #[case("max-age=1.5", true)]
    #[case("s-maxage=1.5", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("max-age=1!", true)]
    #[case("private=Set Cookie", true)]
    #[case("private=\"Set Cookie\"", true)]
    #[case("private=bad@val", true)]
    #[case("private=,", true)]
    #[case("private=\",\"", true)]
    #[case("ma x=1", true)]
    #[case("custom=\"unterminated", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    #[case("foo=bar", false)]
    #[case("max-age=abc", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("custom=\"unterminated", true)]
    #[case("max-age=1!", true)]
    #[case("private=,", true)]
    #[case("ma x=1", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[test]
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
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
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlDirectiveValid;
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
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn whitespace_only_request_is_allowed() -> anyhow::Result<()> {
        // Leading/trailing OWS is excluded from the field line value (RFC 9112
        // §5.1), so a whitespace-only value is an empty value: a legal
        // zero-element list, exactly like `empty_whole_value_is_allowed_request`.
        let rule = CacheControlDirectiveValid;
        let tx = make_req("   ");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "whitespace-only value is an empty field line value, i.e. a zero-element list"
        );
        Ok(())
    }

    #[test]
    fn whitespace_only_response_is_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("   ");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "whitespace-only value is an empty field line value, i.e. a zero-element list"
        );
        Ok(())
    }

    #[test]
    fn private_unterminated_quoted_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"unterminated");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some(),
            "unterminated quoted-string in private value should be a violation"
        );
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
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
    fn empty_whole_value_is_allowed_request() -> anyhow::Result<()> {
        // A wholly empty `Cache-Control:` is a legal zero-element list, unlike the
        // empty *element* in `empty_member_is_violation`.
        let rule = CacheControlDirectiveValid;
        let tx = make_req("");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "empty Cache-Control is a zero-element list");
        Ok(())
    }

    #[test]
    fn empty_whole_value_is_allowed_response() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "empty Cache-Control is a zero-element list");
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = CacheControlDirectiveValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "cache_control_directive_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn foo_empty_value_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
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
    fn foo_quoted_value_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=\"bar\"");
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
    fn directive_value_invalid_token() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=bad@val");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    /// `delta-seconds = 1*DIGIT` sets no upper bound, and §1.2.2 tells a cache that
    /// receives an unrepresentable value to clamp it to 2147483648 rather than treat
    /// it as an error — so an oversized digit run is valid syntax, not a violation.
    #[rstest]
    #[case("max-age=18446744073709551616")]
    #[case("s-maxage=99999999999999999999999999")]
    fn oversized_delta_seconds_is_valid_syntax(#[case] value: &str) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(value);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        Ok(())
    }

    #[test]
    fn empty_directive_name_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("=bar");
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
    fn private_quoted_empty_field_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"field1,,field3\"");
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
    fn private_quoted_invalid_field_char_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"field1,bad@field\"");
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
    fn response_non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlDirectiveValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
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
    fn whitespace_around_name_value_accepted() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(" max-age = 3600 ");
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
    fn quoted_string_with_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
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
    fn multiple_directives_unquoted_comma_accepted() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=bar,baz");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }
}
