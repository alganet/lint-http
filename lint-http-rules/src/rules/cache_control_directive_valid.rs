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

pub struct CacheControlDirectiveValid;

/// The eight defects `cache_control_token_valid` declares, declared here for a
/// second time and by a rule that reads a *different* question of the same
/// members.
///
/// § 1.2.1 is why the ids transfer with nothing to decide: RFC 9111 imports
/// `token`, `quoted-string` and `field-name` from RFC 9110 by reference and
/// takes the `#` list construct from § 5.6.1, so every production this rule
/// measures is one another field already reports through. What stays unnamed is
/// the part its neighbour does not read — what each *named* directive means by
/// its argument — which is the only thing left here that no production says.
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
const RFC_9111_1_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("1.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.1",
    note: "Imported Rules — `token`, `quoted-string` and `field-name` are RFC 9110's, \
           taken by reference and not restated, which is why a directive's parts report \
           the same defects as any other field written out of them",
};

/// One finding from the reading, and the defect it reports as where the
/// catalogue names that defect.
///
/// The shape `expect_header_valid` settled: a judge that is half converted says
/// so in its type. The unnamed half here is what the rule is *named* for — a
/// `max-age` argument that is a token but not `delta-seconds`, and a qualified
/// directive whose argument lists no field at all — both of which are RFC 9111
/// saying what a particular directive means by its argument, which is a
/// statement no production carries.
struct Defect {
    def: Option<&'static ViolationDef>,
    message: String,
}

impl Defect {
    /// A defect the catalogue names.
    fn named(def: &'static ViolationDef, message: String) -> Self {
        Self {
            def: Some(def),
            message,
        }
    }

    /// A defect no subject has claimed, reported at the rule's severity the way
    /// every finding here was before the catalogue existed.
    fn unnamed(message: String) -> Self {
        Self { def: None, message }
    }
}

impl CacheControlDirectiveValid {
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
            if let Some(defect) = member_defect(member) {
                let message = format!(
                    "Invalid Cache-Control header in {}: {}",
                    side, defect.message
                );
                return Some(match defect.def {
                    Some(def) => ctx.report_with(def, message),
                    None => self.violation(ctx.severity, message),
                });
            }
        }
        None
    }
}

impl RuleMeta for CacheControlDirectiveValid {
    fn id(&self) -> &'static str {
        "cache_control_directive_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Cache-Control` directive names and argument formats for common correctness issues. This rule enforces directive-specific semantics such as:\n\n- `max-age` and `s-maxage` must have non-negative integer values (delta-seconds).\n- `private` and `no-cache` when carrying a field-name-list must provide a comma-separated list of field-names (tokens) either as an unquoted list or inside a quoted-string.\n- Unquoted directive values must follow the `token` grammar and quoted values must be valid `quoted-string`s.\n\nThis rule complements `cache_control_token_valid` which enforces general token/quoted-string syntax."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_2,
            RFC_9111_1_2_1,
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

impl Rule for CacheControlDirectiveValid {
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
/// The name is read by the shared strict reader, which owns the three defects
/// the two Cache-Control syntax rules report identically. What this rule adds is
/// the part that is its own: what each *named* directive's argument may say.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
fn member_defect(member: &str) -> Option<Defect> {
    let directive = match crate::helpers::cache_control::read_member(member) {
        Ok(directive) => directive,
        // The three defects the reader names are the list's and the token's,
        // and both rules reading this field now answer with the same ids for
        // them. Their *sentences* were already one, because the reader words
        // them; what could not be shared until now is which defect they are.
        Err(defect) => {
            return Some(Defect::named(
                cache_directive_member(defect),
                defect.message(),
            ))
        }
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
                // Asked before the digits, and answered by the catalogue: an
                // argument holding a character no `tchar` admits is not a
                // `cache-directive`'s unquoted argument at all, which is a
                // defect of the production every directive's argument is
                // written in rather than of what *this* directive counts.
                return Some(Defect::named(
                    token_character(c),
                    format!("{} value contains invalid character: '{}'", name, c),
                ));
            }
            if argument.chars().any(|ch| !ch.is_ascii_digit()) {
                // A well-formed token that is not a number. `delta-seconds` is
                // this directive's own argument syntax and no shared production
                // is broken by `-1` or `1.5` — both are tokens — so the finding
                // stays the rule's.
                return Some(Defect::unnamed(format!(
                    "{} must be a non-negative integer",
                    name
                )));
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
                if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(argument) {
                    return Some(Defect::named(
                        quoted_string_defect(defect),
                        format!(
                            "Invalid quoted-string in directive {} value: {}",
                            name,
                            defect.message(argument)
                        ),
                    ));
                }
                return None;
            }
            crate::helpers::token::find_invalid_token_char(argument).map(|c| {
                Defect::named(
                    token_character(c),
                    format!(
                        "Directive {} value contains invalid character: '{}'",
                        name, c
                    ),
                )
            })
        }
    }
}

/// The `#field-name` argument `private` and `no-cache` share, quoted or bare.
///
/// The two spellings ask the same question of each name, which is why the walk
/// below is written once over whichever list the argument turned out to be.
///
/// **Every part of this argument is borrowed and the argument syntax says so.**
/// `#field-name` is § 5.6.1's list construct around § 5.1's `field-name`, which
/// is a `token` — so a stray comma inside the argument is the same defect as a
/// stray comma between directives, and a `@` in a field name is the same defect
/// as a `@` in a directive name. One sentence is left over, and it is the one
/// this rule is named for: an argument that lists *no* field name.
///
/// cite(RFC 9111 § 5.2.2.7, label: private argument syntax): "This directive uses the quoted-string form of the argument syntax."
/// cite(RFC 9110 § 5.1): "A field name labels the corresponding field value as having the semantics defined by that name."
fn field_name_list_defect(name: &str, argument: &str) -> Option<Defect> {
    let list = if argument.starts_with('"') {
        match crate::helpers::quoted_string::unescape_quoted_string(argument) {
            Ok(inner) => inner,
            Err(defect) => {
                return Some(Defect::named(
                    quoted_string_defect(defect),
                    format!(
                        "Invalid quoted-string in {} value: {}",
                        name,
                        defect.message(argument)
                    ),
                ))
            }
        }
    } else {
        // unquoted: allow single token or comma-separated tokens
        argument.to_string()
    };

    // The empty list and the empty element reach the same line below and are
    // not the same statement. `#field-name` is a plain `#`, so an argument of
    // nothing is a zero-element list the production generates — what is wrong
    // with `private=""` is that the *qualified* form is defined as listing one
    // or more field names, which is § 5.2.2.7's sentence and no subject's.
    // `private=","` is the other one: an element a sender wrote and left blank.
    // cite(RFC 9110 § 5.6.1): "#element => [ element ] *( OWS "," OWS [ element ] )"
    let lists_no_field = list.trim().is_empty();

    for field in list.split(',') {
        let field = field.trim();
        if field.is_empty() {
            let message = format!("Empty field-name in {} value", name);
            return Some(match lists_no_field {
                true => Defect::unnamed(message),
                false => Defect::named(&LIST_MEMBER_EMPTY, message),
            });
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(field) {
            return Some(Defect::named(
                token_character(c),
                format!("{} includes invalid field-name character: '{}'", name, c),
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
    fn an_obs_text_octet_in_a_directive_name_is_a_token_defect() -> anyhow::Result<()> {
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
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in request: Directive name contains invalid character: 0xFF"
        );
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
    fn a_responses_obs_text_octet_is_the_same_token_defect() -> anyhow::Result<()> {
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
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in response: Directive name contains invalid character: 0xFF"
        );
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

    /// Every finding whose defect belongs to a production RFC 9111 imports,
    /// with the id it now carries. The rows are the whole of this rule's
    /// borrowed half: the list construct around the directives, the list
    /// construct *inside* a qualified argument, the `token` a directive name, a
    /// directive value and a `field-name` all have to be, and the
    /// `quoted-string` either of the two argument forms may use.
    #[rstest]
    #[case(",max-age=1", "list_member_empty")]
    #[case("private=\"field1,,field3\"", "list_member_empty")]
    #[case("=bar", "token_empty")]
    #[case("ma x=1", "token_whitespace_or_control_forbidden")]
    #[case("ma@x=1", "token_character_forbidden")]
    #[case("max-age=1@2", "token_character_forbidden")]
    #[case("foo=bad@val", "token_character_forbidden")]
    #[case("private=\"field1,bad@field\"", "token_character_forbidden")]
    #[case("private=\"Set Cookie\"", "token_whitespace_or_control_forbidden")]
    #[case("custom=\"unterminated", "quoted_string_delimiter_missing")]
    #[case("private=\"unterminated", "quoted_string_delimiter_missing")]
    fn a_borrowed_production_reports_the_id_of_the_production(
        #[case] value: &str,
        #[case] id: &str,
    ) {
        assert_eq!(judge(value).violation, id, "{value}");
    }

    /// The two rules that read this field's members answer with one id apiece
    /// for the defects they share.
    ///
    /// The last column is where the sentence comes from, and the two halves of
    /// this table are the difference the catalogue makes. Above it, the member
    /// reader words the finding and both rules pass its sentence on unchanged —
    /// prose deduplicated by sharing code, which was possible before any of
    /// this. Below it, each rule words the argument's finding itself and the
    /// two texts differ; only the id makes them one defect.
    #[test]
    fn both_cache_control_syntax_rules_report_one_id_for_one_mistake() {
        let judge_with = |rule: &dyn crate::rules::Rule, value: &str| -> Violation {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("cache-control", value)]);
            crate::test_helpers::run_rule(
                rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .unwrap_or_else(|| panic!("{}: {value}", rule.id()))
        };

        for (value, id, one_sentence) in [
            ("no-cache,,foo", "list_member_empty", true),
            ("=abc", "token_empty", true),
            ("foo=bad@value", "token_character_forbidden", false),
            (
                "foo=\"unterminated",
                "quoted_string_delimiter_missing",
                false,
            ),
        ] {
            let directive = judge_with(&CacheControlDirectiveValid, value);
            let token = judge_with(
                &crate::rules::cache_control_token_valid::CacheControlTokenValid,
                value,
            );
            assert_eq!(directive.violation, id, "{value}");
            assert_eq!(token.violation, id, "{value}");
            assert_eq!(directive.message == token.message, one_sentence, "{value}");
        }
    }

    /// What this rule is named for keeps its own severity and no id: RFC 9111
    /// saying what a *particular* directive means by its argument is a
    /// statement none of the productions carries.
    #[rstest]
    #[case("max-age=-1")]
    #[case("max-age=1.5")]
    #[case("s-maxage=1.5")]
    #[case("max-age=abc")]
    fn what_a_directive_counts_is_not_a_productions_defect(#[case] value: &str) {
        assert_eq!(judge(value).violation, "", "{value}");
    }

    /// One line, two statements, and the argument syntax is what separates
    /// them. `#field-name` generates the empty list, so an argument listing
    /// nothing breaks § 5.2.2.7's definition of the qualified form and not
    /// § 5.6.1.1's MUST NOT — which forbids an element a sender wrote and left
    /// blank, and is exactly what the comma in the second value is.
    #[test]
    fn the_empty_list_and_the_empty_element_are_two_statements() {
        let empty_list = judge("private=\"\"");
        let empty_element = judge("private=\",\"");
        assert_eq!(empty_list.message, empty_element.message);
        assert_eq!(empty_list.violation, "");
        assert_eq!(empty_element.violation, "list_member_empty");
    }

    /// Read a value's first finding, which every assertion above wants.
    fn judge(value: &str) -> Violation {
        let rule = CacheControlDirectiveValid;
        crate::test_helpers::run_rule(
            &rule,
            &make_req(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("expected a finding for '{value}'"))
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
