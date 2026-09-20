// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::token_list::{token_list_defects, TokenListDefect};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::delta_seconds::{
    DELTA_SECONDS_CHARACTER_FORBIDDEN, DELTA_SECONDS_EMPTY, RFC_9111_1_2_2,
};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::method::{METHOD_CASE_INVALID, RFC_9110_9_1};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

/// The four response fields of Fetch § 3.3.4 whose values nothing read.
///
/// **Not one of these entries is this rule's own, and that is the finding
/// rather than a shortcut.** § 3.3.4 writes nine productions and names three
/// that are somebody else's in as many words: `Access-Control-Max-Age =
/// delta-seconds` is RFC 9111 § 1.2.2's, `#field-name` and `#method` are
/// RFC 9110 § 5.6.2's `token` inside § 5.6.1's list. Every one of them already
/// had a reader and entries in this tree — `Age` and `Cache-Control` read the
/// first, `Vary` and `Allow` the other two — and these four fields carried the
/// same productions past no reader at all. So what this rule adds is the
/// reading, and the ids stay where the production put them.
pub struct CorsResponseHeaderSyntax;

/// Six entries and none of them new.
///
/// [`METHOD_CASE_INVALID`] is the one that is not a grammar defect: `get`
/// derives from `1*tchar` exactly as `GET` does, and what refuses it is § 9.1's
/// case-sensitivity one level past the production. It sits here for the same
/// reason it sits on the rule that reads a request-line — a server matching
/// method names byte-for-byte sees an unrecognized method — and it costs this
/// rule the `registered_methods` array, because the convention is evidence and
/// not a grammar and there is no list of standardized names a rule may compile
/// in.
static DECLARED: &[&ViolationDef] = &[
    &DELTA_SECONDS_EMPTY,
    &DELTA_SECONDS_CHARACTER_FORBIDDEN,
    &LIST_MEMBER_EMPTY,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_CHARACTER_FORBIDDEN,
    &METHOD_CASE_INVALID,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const FETCH_3_3_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.3.4"),
    url: "https://fetch.spec.whatwg.org/#http-new-header-syntax",
    note: "ABNF for the CORS protocol's header values. The four response fields read here — \
           `Access-Control-Expose-Headers = #field-name`, `Access-Control-Allow-Headers = \
           #field-name`, `Access-Control-Allow-Methods = #method` and `Access-Control-Max-Age = \
           delta-seconds` — name productions three other documents define, and none of the four \
           adds punctuation of its own",
};
const FETCH_3_3_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.3.3"),
    url: "https://fetch.spec.whatwg.org/#http-responses",
    note: "Which of these fields a CORS response may carry, and that `*` counts as a wildcard in \
           the three list-valued ones for requests without credentials — which needs no arm in \
           the reading, `tchar` admitting the asterisk",
};

impl RuleMeta for CorsResponseHeaderSyntax {
    fn id(&self) -> &'static str {
        "cors_response_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# The standardized method names this deployment expects to see spelled the way their
# definitions spell them, used only by the `Access-Control-Allow-Methods` reading.
# Fetch compares a method in that field against the request's method byte-for-byte,
# so `get` allows nothing — but `get` is a perfectly good `token`, and only a list of
# names makes the lowercase spelling recognisable as a mistake rather than as somebody's
# private method. The same array `request_method_token_valid` takes, for the same reason.
registered_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("CORS Response Header Syntax")
    }

    fn description(&self) -> &'static str {
        "Reads the four CORS response header values Fetch §3.3.4 gives a grammar and no rule read: `Access-Control-Expose-Headers = #field-name`, `Access-Control-Allow-Headers = #field-name`, `Access-Control-Allow-Methods = #method` and `Access-Control-Max-Age = delta-seconds`.\n\nNone of the four adds punctuation of its own, so every syntactic finding here is a statement about a production some other document owns, reported under that production's id: a member holding an octet `tchar` does not admit is the same defect a `Vary` field name or an `Allow` method has, and a `max-age` that is not `1*DIGIT` is the same defect an `Age` has. What stays the field's is what the tokens *mean*.\n\nThe three list-valued fields are `#`-lists, so a value with nothing on it is a legal zero-element list and draws nothing; an empty element *within* a list — a leading, trailing or doubled comma — is reported once for the line. `*` needs no special case: Fetch gives it a meaning of its own in these three fields and `tchar` admits it, so it is a `token` before it is a wildcard.\n\nOne finding here is not a grammar defect. A method in `Access-Control-Allow-Methods` written as a standardized name in another case — `get` for `GET` — parses perfectly and allows nothing, because Fetch matches it against the request's method byte-for-byte. Reporting it needs the `registered_methods` array, for the reason `request_method_token_valid` needs it: the convention is what makes a lowercase spelling recognisable as a mistake, and no rule may compile in a registry that grows by IETF Review.\n\nWhat this rule does not decide: whether the fields should be present at all (`options_method_capabilities` reads that), whether `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` agree (their own rules read those two of §3.3.4's productions), and whether a named header or method is one the resource actually has."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            FETCH_3_3_4,
            FETCH_3_3_3,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_9_1,
            RFC_9111_1_2_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let state = crate::helpers::rule_config::registered_methods(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(state),
        })
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Allow-Methods: GET, POST\nAccess-Control-Allow-Headers: Content-Type\nAccess-Control-Max-Age: 86400",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("a `#`-list derives the empty list, and `tchar` admits the asterisk"),
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Expose-Headers: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`#field-name` is comma-separated, so this is one member holding a space and it exposes nothing"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Expose-Headers: Content-Length Content-Range",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a field-name is a token, and `:` is no tchar"),
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Allow-Headers: Content-Type:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("an empty element within the list"),
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Allow-Methods: GET,,POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("the method token is case-sensitive, so this allows nothing"),
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Allow-Methods: get, POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`delta-seconds` is `1*DIGIT` and admits no sign"),
                snippet: "HTTP/1.1 204 No Content\nAccess-Control-Max-Age: -1",
            },
        ]
    }
}

/// The three `#token` fields, and what each member of one is called in a
/// finding. The noun is the field's, because a `field-name` and a `method` are
/// the same production and not the same mistake to an operator reading the
/// sentence.
const TOKEN_LIST_FIELDS: &[(&str, &str)] = &[
    ("access-control-expose-headers", "field-name"),
    ("access-control-allow-headers", "field-name"),
    ("access-control-allow-methods", "method"),
];

impl Rule for CorsResponseHeaderSyntax {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        let config: &crate::helpers::rule_config::RegisteredMethods = ctx.state();

        let mut out = Vec::new();

        for (field, noun) in TOKEN_LIST_FIELDS {
            // Per line rather than joined. A field repeated on two lines is
            // `field_line_duplicated`'s finding and not this rule's, and joining
            // the lines here would invent a comma the sender did not write and
            // then read the value across it.
            for line in crate::helpers::headers::field_lines_as_written(&resp.headers, field) {
                for defect in token_list_defects(&line) {
                    out.push(report(ctx, field, noun, defect));
                }

                // The case reading is `#method`'s alone: a `field-name` is
                // matched case-insensitively (§ 5.1) and a method is not.
                if *field == "access-control-allow-methods" {
                    out.extend(method_case_findings(ctx, &line, &config.registered_methods));
                }
            }
        }

        out.extend(max_age_findings(ctx, &resp.headers));
        out
    }
}

/// One member's defect, worded for the field it was written in.
fn report(
    ctx: &crate::rules::RuleContext<'_>,
    field: &str,
    noun: &str,
    defect: TokenListDefect<'_>,
) -> Violation {
    match defect {
        // What § 5.6.1.1 forbids generating is an empty element, and the
        // sentence that says so is on the def, where the twenty-odd other
        // fields reporting a stray comma read the same one.
        TokenListDefect::EmptyMember => ctx.report_with(
            &LIST_MEMBER_EMPTY,
            format!(
                "{} is a comma-separated list of `{noun}`s and holds an empty element \
                 (a leading, trailing or doubled comma)",
                header_name(field)
            ),
        ),
        // The member is named because the octet does not identify it: a value
        // offending in two members would otherwise say one sentence twice and
        // an operator could not tell which half to fix.
        TokenListDefect::Character { member, offending } => ctx.report_with(
            token_character(offending),
            format!(
                "{} member '{}' contains {}, which is not a `tchar`, so it derives from no \
                 `token` and therefore from no `{noun}`",
                header_name(field),
                crate::helpers::shown::shown_in_finding(member),
                crate::helpers::shown::describe_char(offending)
            ),
        ),
    }
}

/// `Access-Control-Allow-Methods`' members that are a standardized method's
/// name written in another case.
///
/// Only the members that are `token`s to begin with are asked: a member the
/// walk above already refused derives from no `method` at all, and folding it
/// to compare against a registry would be asking whether a value that is not a
/// method is the wrong sort of method.
fn method_case_findings(
    ctx: &crate::rules::RuleContext<'_>,
    line: &str,
    registered: &[String],
) -> Vec<Violation> {
    let mut out = Vec::new();
    for member in crate::helpers::list::list_members(line) {
        if crate::helpers::token::find_invalid_token_char(member).is_some() {
            continue;
        }
        if crate::helpers::token::find_first_lowercase(member).is_none() {
            continue;
        }
        let folded = member.to_ascii_uppercase();
        if !registered.iter().any(|r| r == &folded) {
            continue;
        }
        // Fetch's preflight compares this field's members against the request's
        // method byte-for-byte, and § 9.1 says why the comparison is that way —
        // so a lowercase spelling here is a value that allows nothing, and the
        // response says it allows something.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        out.push(ctx.report_with(
            &METHOD_CASE_INVALID,
            format!(
                "Access-Control-Allow-Methods member '{}' is '{folded}' written in another case. \
                 The method token is case-sensitive, so this member allows no method",
                crate::helpers::shown::shown_in_finding(member)
            ),
        ));
    }
    out
}

/// `Access-Control-Max-Age = delta-seconds`, and nothing else.
///
/// § 3.3.4 names the production and adds no punctuation, so both findings are
/// `1*DIGIT`'s. Fetch's *"if max-age is failure or null, then set max-age to
/// 5"* is a recipient's instruction and not a licence: § 1.2.2's clamp is the
/// same shape one document over, and the module that owns the production has
/// already read it that way.
fn max_age_findings(
    ctx: &crate::rules::RuleContext<'_>,
    headers: &hyper::HeaderMap,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for line in crate::helpers::headers::field_lines_as_written(headers, "access-control-max-age") {
        let s = crate::helpers::headers::trim_ows(&line);
        if s.is_empty() {
            out.push(
                ctx.report_with(
                    &DELTA_SECONDS_EMPTY,
                    "Access-Control-Max-Age states no time: `delta-seconds` is `1*DIGIT` and this \
                 value has no digits"
                        .into(),
                ),
            );
            continue;
        }
        if let Some(c) = s.chars().find(|c| !c.is_ascii_digit()) {
            out.push(ctx.report_with(
                &DELTA_SECONDS_CHARACTER_FORBIDDEN,
                format!(
                    "Access-Control-Max-Age value '{}' is invalid: {} is no `DIGIT`, so the \
                     value is not the `delta-seconds` the field is",
                    crate::helpers::shown::shown_in_finding(s),
                    crate::helpers::shown::describe_char(c),
                ),
            ));
        }
    }
    out
}

/// The field name as a sender writes it, for a sentence an operator reads
/// beside their own configuration.
fn header_name(field: &str) -> &'static str {
    match field {
        "access-control-expose-headers" => "Access-Control-Expose-Headers",
        "access-control-allow-headers" => "Access-Control-Allow-Headers",
        _ => "Access-Control-Allow-Methods",
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CorsResponseHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cors_response_header_syntax",
        ]);
        let mut table = toml::map::Map::new();
        table.insert("enabled".into(), toml::Value::Boolean(true));
        table.insert(
            "registered_methods".into(),
            toml::Value::Array(
                ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
                    .iter()
                    .map(|m| toml::Value::String((*m).into()))
                    .collect(),
            ),
        );
        cfg.rules.insert(
            "cors_response_header_syntax".into(),
            toml::Value::Table(table),
        );
        cfg
    }

    fn run(headers: &[(&str, &str)]) -> Vec<Violation> {
        let rule = CorsResponseHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(204, headers);
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    fn ids(headers: &[(&str, &str)]) -> Vec<String> {
        run(headers).into_iter().map(|v| v.violation).collect()
    }

    /// Every value §3.3.4 generates, including the two shapes that look like
    /// defects and are not: a `#`-list's empty value and the asterisk `tchar`
    /// admits.
    #[rstest]
    #[case(&[("access-control-allow-methods", "GET, HEAD, POST")])]
    #[case(&[("access-control-allow-headers", "Content-Type,Authorization")])]
    #[case(&[("access-control-expose-headers", "*")])]
    #[case(&[("access-control-allow-methods", "*")])]
    #[case(&[("access-control-expose-headers", "")])]
    #[case(&[("access-control-max-age", "0")])]
    #[case(&[("access-control-max-age", "86400")])]
    // A run of digits too wide to represent is a conforming `delta-seconds`
    // that §1.2.2 tells a recipient to clamp, so it is not this rule's finding.
    #[case(&[("access-control-max-age", "99999999999999999999999")])]
    fn a_conforming_value_draws_nothing(#[case] headers: &[(&str, &str)]) {
        assert_eq!(ids(headers), Vec::<String>::new(), "for {headers:?}");
    }

    /// The four productions, each broken in the way its own document names.
    #[rstest]
    #[case::expose_space(
        &[("access-control-expose-headers", "Content-Length Content-Range")],
        "token_whitespace_or_control_forbidden"
    )]
    #[case::expose_gap(
        &[("access-control-expose-headers", "X-Foo,,X-Baz")],
        "list_member_empty"
    )]
    #[case::allow_headers_colon(
        &[("access-control-allow-headers", "Content-Type:")],
        "token_character_forbidden"
    )]
    #[case::allow_methods_at(
        &[("access-control-allow-methods", "GET, PO@T")],
        "token_character_forbidden"
    )]
    #[case::allow_methods_case(
        &[("access-control-allow-methods", "get, POST")],
        "method_case_invalid"
    )]
    #[case::max_age_sign(&[("access-control-max-age", "-1")], "delta_seconds_character_forbidden")]
    #[case::max_age_alpha(&[("access-control-max-age", "abc")], "delta_seconds_character_forbidden")]
    #[case::max_age_empty(&[("access-control-max-age", "")], "delta_seconds_empty")]
    fn each_defect_names_its_production(#[case] headers: &[(&str, &str)], #[case] expected: &str) {
        assert_eq!(ids(headers), vec![expected.to_string()], "for {headers:?}");
    }

    /// The value the counted web actually carries: a server that meant to
    /// expose two headers and wrote them the way a `Vary` is *not* written, so
    /// a browser reads one member matching no header and exposes neither.
    #[test]
    fn a_space_separated_expose_headers_names_the_member_it_read() {
        let v = run(&[(
            "access-control-expose-headers",
            "Access-Control-Allow-Origin Access-Control-Allow-Credentials",
        )]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].violation, "token_whitespace_or_control_forbidden");
        assert!(
            v[0].message
                .contains("'Access-Control-Allow-Origin Access-Control-Allow-Credentials'"),
            "{}",
            v[0].message
        );
        assert!(v[0].message.contains("field-name"), "{}", v[0].message);
    }

    /// The noun is the field's. Both fields are `token` lists and the same
    /// octet is wrong in both, but an operator reading the sentence is looking
    /// for one of two different things.
    #[test]
    fn the_sentence_names_what_the_member_was_meant_to_be() {
        let headers = run(&[("access-control-allow-headers", "X Y")]);
        assert!(headers[0].message.contains("`field-name`"), "{:?}", headers);
        let methods = run(&[("access-control-allow-methods", "G T")]);
        assert!(methods[0].message.contains("`method`"), "{:?}", methods);
    }

    /// A value can be wrong in two members, and each is its own finding — the
    /// reason [`TokenListDefect::Character`] carries the member at all.
    #[test]
    fn every_offending_member_is_reported() {
        let v = run(&[("access-control-allow-headers", "X@Foo, Y@Bar")]);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v[0].message.contains("'X@Foo'"), "{}", v[0].message);
        assert!(v[1].message.contains("'Y@Bar'"), "{}", v[1].message);
    }

    /// A member that is no `token` is not then asked whether it is a method
    /// spelled wrong: the fold would be measuring a value that derives from no
    /// `method` at all against a list of method names.
    #[test]
    fn a_member_that_is_no_token_is_not_also_a_case_finding() {
        let v = run(&[("access-control-allow-methods", "ge t")]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].violation, "token_whitespace_or_control_forbidden");
    }

    /// The convention is evidence and not a grammar: an uppercase name absent
    /// from the array is very often somebody's private method, and a lowercase
    /// one nobody standardized is the same value.
    #[test]
    fn only_a_name_the_deployment_expects_draws_the_case_finding() {
        assert_eq!(
            ids(&[("access-control-allow-methods", "purge")]),
            Vec::<String>::new()
        );
        assert_eq!(
            ids(&[("access-control-allow-methods", "PURGE")]),
            Vec::<String>::new()
        );
    }

    /// Each line answers for itself. Joining them would invent a comma the
    /// sender never wrote and read a value across it.
    #[test]
    fn a_repeated_field_answers_once_per_line() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = CorsResponseHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-headers", "X@Foo")]);
        hdrs.append(
            "access-control-allow-headers",
            HeaderValue::from_static("Y@Bar"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 204,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let v = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        );
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn no_response_no_finding() {
        let rule = CorsResponseHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        assert!(crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .is_empty());
    }

    #[test]
    fn needs_a_response() {
        assert!(CorsResponseHeaderSyntax.needs_response());
    }

    /// The array is what the case reading leans on, so its absence is a
    /// configuration error rather than a rule that quietly checks less.
    #[test]
    fn the_registered_methods_array_is_required() {
        let rule = CorsResponseHeaderSyntax;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".into(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cors_response_header_syntax".into(),
            toml::Value::Table(table),
        );
        assert!(rule.prepare(&cfg).is_err());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        CorsResponseHeaderSyntax.prepare(&cfg()).map(|_| ())
    }
}
