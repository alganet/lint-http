// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::cookie::find_invalid_cookie_octet;
use crate::helpers::headers::field_line_as_written;
use crate::helpers::token::find_invalid_token_char;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::{
    COOKIE_PAIR_EQUALS_MISSING, COOKIE_VALUE_CHARACTER_FORBIDDEN, RFC_6265_4_1_1, RFC_6265_4_2_1,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CookiePairValid;

/// `cookie-name` is not this rule's own defect: `cookie-name = token` imports
/// the production `Set-Cookie`'s own reader already reports under, and a name
/// that fails it is the same defect under the same id whichever field carried
/// it. What is left is `cookie-pair` and `cookie-value`, which the request
/// side had no reader for at all.
static DECLARED: &[&ViolationDef] = &[
    &COOKIE_PAIR_EQUALS_MISSING,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &COOKIE_VALUE_CHARACTER_FORBIDDEN,
];

/// The sentence that makes an off-grammar `Cookie` value reportable at all.
/// § 4.2.1 itself binds nobody: it describes what a user agent sends *given*
/// that the server and the user agent already conform, not what any sender
/// must produce.
const RFC_9110_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
    note: "The MUST NOT that makes a value outside the field's ABNF a finding, since §4.2.1 states no keyword of its own",
};

impl RuleMeta for CookiePairValid {
    fn id(&self) -> &'static str {
        "cookie_pair_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "This rule measures the `Cookie` request header against RFC 6265 §4.2.1's grammar: `cookie-string = cookie-pair *( \";\" SP cookie-pair )`, `cookie-pair = cookie-name \"=\" cookie-value`, `cookie-name = token`, `cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )`. Each field line is split on `;` into cookie-pairs, and each pair is judged on its own: a segment with no `=` at all, a `cookie-name` that is not a `token` (reported under the same shared id `Set-Cookie`'s cookie-name already uses), and a `cookie-value` carrying an octet outside `cookie-octet` — a comma, a semicolon, a backslash, a bare double-quote, whitespace, a control character, or anything above %x7E, unless the whole value is wrapped in a matching pair of double quotes, which `cookie-octet` also allows. §4.2.1 states no keyword of its own about the value a sender constructs — it only describes what a user agent sends given that the server and the user agent already conform — so what makes a non-conforming value reportable is RFC 9110 §2.2's blanket MUST NOT on generating a protocol element outside its grammar. A `Cookie` header split across several field lines (RFC 9113 §8.2.3, HTTP/2 and HTTP/3) is judged one line at a time, since each line is independently a well-formed `cookie-string`. A stray empty segment between two `;`s (`a=1;;b=2`) is tolerated rather than reported, matching this crate's treatment of `Set-Cookie`'s attribute list. Whether a request should carry a `Cookie` field at all, and whether its value matches what was last set, are different questions this rule does not ask."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_6265_4_2_1, RFC_6265_4_1_1, RFC_9110_2_2, RFC_9110_5_6_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The `Cookie` field is the client's own construction: RFC 6265 §5.4
    /// hands it to "the algorithm the user agent runs when generating an HTTP
    /// request", and there is no response half of it for a server to write.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the section's own example)"),
                snippet: "GET / HTTP/1.1\nCookie: SID=31d4d96e407aad42",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(more than one pair)"),
                snippet: "GET / HTTP/1.1\nCookie: SID=31d4d96e407aad42; lang=en-US",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a quoted cookie-value)"),
                snippet: "GET / HTTP/1.1\nCookie: SID=\"31d4d96e407aad42\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no '=' in a pair)"),
                snippet: "GET / HTTP/1.1\nCookie: SID",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(cookie-name is not a token)"),
                snippet: "GET / HTTP/1.1\nCookie: S ID=31d4d96e407aad42",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a comma is not a cookie-octet)"),
                snippet: "GET / HTTP/1.1\nCookie: SID=31d4,d96e",
            },
        ]
    }
}

impl Rule for CookiePairValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector. Every `Cookie` field line
        // is a separate `cookie-string`, and every `;`-separated segment on a
        // line is a separate `cookie-pair`, so `find_map` walks both without
        // one reading standing in for the other.
        let finding = || -> Option<Violation> {
            tx.request
                .headers
                .get_all("cookie")
                .iter()
                .find_map(|hv| self.line_defect(&field_line_as_written(hv), ctx))
        };
        Vec::from_iter(finding())
    }
}

impl CookiePairValid {
    /// The first defect on one `Cookie` field line, if it has one.
    ///
    // cite(RFC 6265 § 4.2.1): "cookie-string = cookie-pair *( ";" SP cookie-pair )"
    fn line_defect(&self, line: &str, ctx: &crate::rules::RuleContext<'_>) -> Option<Violation> {
        line.split(';')
            .map(str::trim)
            // A stray `;;` or a leading/trailing `;` produces an empty
            // segment, which is this reader's own tolerance rather than a
            // pair with nothing between its delimiters — `Set-Cookie`'s
            // attribute list is read the same way.
            .filter(|segment| !segment.is_empty())
            .find_map(|segment| self.pair_defect(segment, ctx))
    }

    /// The defect in one `cookie-pair`, if it has one.
    ///
    /// `cookie-pair` and `cookie-name` are not defined in this field's own
    /// § 4.2.1: they are imported by name from `Set-Cookie`'s § 4.1.1, so both
    /// cites below name that section rather than this one.
    // cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
    fn pair_defect(&self, segment: &str, ctx: &crate::rules::RuleContext<'_>) -> Option<Violation> {
        let Some((name, value)) = segment.split_once('=') else {
            return Some(ctx.report_with(
                &COOKIE_PAIR_EQUALS_MISSING,
                format!("Cookie pair '{segment}' has no '=': `cookie-pair = cookie-name \"=\" cookie-value` requires one"),
            ));
        };

        // `cookie-name = token`, the same production `Set-Cookie`'s
        // cookie-name answers to, so a defect here reports under the id that
        // production's other reader already uses.
        if name.is_empty() {
            return Some(ctx.report_with(
                &TOKEN_EMPTY,
                format!("Cookie pair '{segment}' has an empty cookie-name"),
            ));
        }
        if let Some(c) = find_invalid_token_char(name) {
            return Some(ctx.report_with(
                token_character(c),
                format!("Cookie cookie-name '{name}' contains invalid character: '{c}'"),
            ));
        }

        if let Some(c) = find_invalid_cookie_octet(value) {
            return Some(ctx.report_with(
                &COOKIE_VALUE_CHARACTER_FORBIDDEN,
                format!("Cookie value '{value}' contains a character outside cookie-octet: '{c}'"),
            ));
        }

        None
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CookiePairValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(cookie_values: &[&str]) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        let pairs: Vec<(&str, &str)> = cookie_values.iter().map(|v| ("cookie", *v)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        let config =
            crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_pair_valid"]);
        crate::test_helpers::run_rule(
            &CookiePairValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
    }

    #[rstest]
    #[case("SID=31d4d96e407aad42")]
    #[case("SID=31d4d96e407aad42; lang=en-US")]
    #[case("SID=\"31d4d96e407aad42\"")]
    #[case("empty=")]
    // A stray empty segment is tolerated, not reported.
    #[case("a=1;;b=2")]
    #[case("a=1; ;b=2")]
    fn conforming_values_are_silent(#[case] value: &str) {
        assert_eq!(judge(&[value]).map(|v| v.message), None);
    }

    #[rstest]
    #[case("SID", "cookie_pair_equals_missing")]
    #[case("a=1;SID;b=2", "cookie_pair_equals_missing")]
    #[case("=novalue", "token_empty")]
    #[case("S ID=31d4d96e407aad42", "token_whitespace_or_control_forbidden")]
    #[case("SID=31d4,d96e", "cookie_value_character_forbidden")]
    #[case("SID=31d4;d96e", "cookie_pair_equals_missing")]
    #[case("SID=31d4\\d96e", "cookie_value_character_forbidden")]
    #[case("SID=\"31d4 d96e\"", "cookie_value_character_forbidden")]
    // A lone stray quote does not match the wrapped form and is scanned as
    // written, so it is reported rather than silently unwrapped into nothing.
    #[case("SID=\"", "cookie_value_character_forbidden")]
    fn malformed_values_name_their_defect(#[case] value: &str, #[case] violation: &str) {
        let v = judge(&[value]).unwrap_or_else(|| panic!("expected a finding for {value:?}"));
        assert_eq!(v.violation, violation, "{}", v.message);
    }

    /// `SID=31d4;d96e` above split on `;` into `SID=31d4` (fine) and `d96e`
    /// (no `=`) — this is the same value read as one `cookie-string`, which is
    /// the shape a semicolon inside an unquoted value actually produces on the
    /// wire and the reason the character is forbidden in the first place.
    #[test]
    fn a_semicolon_inside_a_value_is_read_as_a_second_pair() {
        let v = judge(&["SID=31d4;d96e"]).expect("a finding");
        assert_eq!(v.violation, "cookie_pair_equals_missing");
    }

    /// Each field line is its own `cookie-string`: a defect on the second line
    /// is still found even though the first is clean, and a clean second line
    /// does not hide a defect on the first.
    #[test]
    fn each_field_line_is_read_independently() {
        assert!(judge(&["SID=31d4d96e407aad42", "bad,name=1"]).is_some());
        assert!(judge(&["bad,name=1", "SID=31d4d96e407aad42"]).is_some());
    }

    #[test]
    fn a_request_with_no_cookie_is_silent() {
        assert!(judge(&[]).is_none());
    }

    #[test]
    fn needs_no_response() {
        assert!(!CookiePairValid.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["cookie_pair_valid"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in CookiePairValid.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            assert!(
                start.ends_with(" HTTP/1.1"),
                "this guard files an example's fields onto the request: {start:?}"
            );
            let fields: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let found = judge(&fields.iter().map(|(_, v)| *v).collect::<Vec<_>>());
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
