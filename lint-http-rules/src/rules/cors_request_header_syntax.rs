// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::token_list::{token_list_defects, TokenListDefect};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{
    LIST_MEMBER_EMPTY, LIST_MEMBER_MISSING, RFC_9110_5_6_1_1, RFC_9110_5_6_1_2,
};
use crate::violations::method::{METHOD_CASE_INVALID, RFC_9110_9_1};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

/// The two request fields of Fetch § 3.3.4 whose values nothing read.
///
/// **The half of the CORS block a client writes.** Fetch splits its own
/// account of the protocol that way — § 3.3.2 is what a preflight sends,
/// § 3.3.3 what a server answers — and the split is the party: every finding
/// here is a client's, and every finding of
/// [`super::cors_response_header_syntax`] is a server's. Grouping the six
/// fields by the *production* they share instead would have put a client's
/// mistake and a server's under one rule and one `party`, and the two lists
/// have nothing to say to each other.
///
/// **The one grammar difference from the response side, and it is the whole
/// reason [`LIST_MEMBER_MISSING`] is declared here and nowhere in that rule.**
/// `Access-Control-Request-Headers = 1#field-name` has a floor; the three
/// response lists are plain `#element` and derive the empty list. So a
/// `Access-Control-Request-Headers:` with nothing on it is a defect here and a
/// legal zero-element list there, which is a fact about two spellings in one
/// ABNF block rather than a preference.
pub struct CorsRequestHeaderSyntax;

/// Six entries and none of them new — the same reading as the response side,
/// plus the `1#` floor and the empty-`token` case a single-valued field has and
/// a list does not.
static DECLARED: &[&ViolationDef] = &[
    &TOKEN_EMPTY,
    &LIST_MEMBER_MISSING,
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
    note: "ABNF for the CORS protocol's header values. The two request fields read here — \
           `Access-Control-Request-Method = method` and `Access-Control-Request-Headers = \
           1#field-name` — name productions RFC 9110 defines, and the `1#` is the one place \
           this block's two list spellings differ",
};
const FETCH_3_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.3.2"),
    url: "https://fetch.spec.whatwg.org/#cors-preflight-request",
    note: "The CORS-preflight request and the two headers it carries: the method a future \
           request might use, and the header names it might carry",
};

impl RuleMeta for CorsRequestHeaderSyntax {
    fn id(&self) -> &'static str {
        "cors_request_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# The standardized method names this deployment expects to see spelled the way their
# definitions spell them, used only by the `Access-Control-Request-Method` reading.
# The preflight names a method a later request will use, and that comparison is
# byte-for-byte — so `get` announces a method nothing defines. But `get` is a perfectly
# good `token`, and only a list of names makes the lowercase spelling recognisable as a
# mistake rather than as somebody's private method. The same array
# `request_method_token_valid` takes, for the same reason.
registered_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("CORS Request Header Syntax")
    }

    fn description(&self) -> &'static str {
        "Reads the two CORS request header values Fetch §3.3.4 gives a grammar and no rule read: `Access-Control-Request-Method = method` and `Access-Control-Request-Headers = 1#field-name`.\n\nNeither field adds punctuation of its own, so every syntactic finding here is a statement about a production RFC 9110 owns, reported under that production's id: a value holding an octet `tchar` does not admit is the same defect a `Vary` field name or an `Allow` method has.\n\n**`Access-Control-Request-Headers` is `1#field-name`, not `#field-name`.** The `1#` has a floor, so a header line written with nothing on it states no header name and is reported — where the three list-valued *response* fields of the same ABNF block are plain `#element`, derive the empty list, and are silent on the same shape. An empty element *within* the list — a leading, trailing or doubled comma — is reported once for the line in both.\n\nOne finding here is not a grammar defect. A method in `Access-Control-Request-Method` written as a standardized name in another case — `get` for `GET` — parses perfectly and announces a method nothing defines, because the preflight's method is compared byte-for-byte. Reporting it needs the `registered_methods` array, for the reason `request_method_token_valid` needs it: the convention is what makes a lowercase spelling recognisable as a mistake, and no rule may compile in a registry that grows by IETF Review.\n\nWhat this rule does not decide: whether a preflight should have been sent at all, whether the server's answer matches what was asked for (`options_method_capabilities` and the `Access-Control-Allow-*` rules read that), and whether the named headers are ones the request would actually carry."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            FETCH_3_3_4,
            FETCH_3_3_2,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_9110_5_6_2,
            RFC_9110_9_1,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
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
                snippet: "OPTIONS /r HTTP/1.1\nHost: example.com\nOrigin: https://app.example\nAccess-Control-Request-Method: POST\nAccess-Control-Request-Headers: Content-Type",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`1#field-name` has a floor, so a line with nothing on it states no header name"),
                snippet: "OPTIONS /r HTTP/1.1\nHost: example.com\nOrigin: https://app.example\nAccess-Control-Request-Method: POST\nAccess-Control-Request-Headers:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`1#field-name` is comma-separated, so this is one member holding a space"),
                snippet: "OPTIONS /r HTTP/1.1\nHost: example.com\nOrigin: https://app.example\nAccess-Control-Request-Method: POST\nAccess-Control-Request-Headers: Content-Type X-Foo",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a method is a token, and `(` is no tchar"),
                snippet: "OPTIONS /r HTTP/1.1\nHost: example.com\nOrigin: https://app.example\nAccess-Control-Request-Method: PO(ST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("the method token is case-sensitive, so this announces a method nothing defines"),
                snippet: "OPTIONS /r HTTP/1.1\nHost: example.com\nOrigin: https://app.example\nAccess-Control-Request-Method: post",
            },
        ]
    }
}

impl Rule for CorsRequestHeaderSyntax {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let config: &crate::helpers::rule_config::RegisteredMethods = ctx.state();
        let headers = &tx.request.headers;
        let mut out = Vec::new();

        // `Access-Control-Request-Headers = 1#field-name`. Per line rather than
        // joined: a field repeated on two lines is `field_line_duplicated`'s
        // finding, and joining would invent a comma the sender did not write.
        for line in crate::helpers::headers::field_lines_as_written(
            headers,
            "access-control-request-headers",
        ) {
            // The floor, and the one reading that separates this field from the
            // response side's three. `#element` derives the empty list and
            // `1#element` does not, so this line states no header name at all.
            // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
            if crate::helpers::list::list_members(&line).next().is_none() {
                out.push(ctx.report_with(
                    &LIST_MEMBER_MISSING,
                    format!(
                        "Access-Control-Request-Headers is `1#field-name` and names no header \
                         field; the request's field line combines to '{}'",
                        crate::helpers::shown::shown_in_finding(crate::helpers::headers::trim_ows(
                            &line
                        ))
                    ),
                ));
                continue;
            }

            for defect in token_list_defects(&line) {
                out.push(match defect {
                    TokenListDefect::EmptyMember => ctx.report_with(
                        &LIST_MEMBER_EMPTY,
                        "Access-Control-Request-Headers is a comma-separated list of \
                         `field-name`s and holds an empty element (a leading, trailing or \
                         doubled comma)"
                            .into(),
                    ),
                    TokenListDefect::Character { member, offending } => ctx.report_with(
                        token_character(offending),
                        format!(
                            "Access-Control-Request-Headers member '{}' contains {}, which is \
                             not a `tchar`, so it derives from no `token` and therefore from no \
                             `field-name`",
                            crate::helpers::shown::shown_in_finding(member),
                            crate::helpers::shown::describe_char(offending)
                        ),
                    ),
                });
            }
        }

        // `Access-Control-Request-Method = method`, and `method = token` — one
        // value, no list, so the empty case is the `token`'s own and not
        // § 5.6.1.1's.
        for line in crate::helpers::headers::field_lines_as_written(
            headers,
            "access-control-request-method",
        ) {
            let s = crate::helpers::headers::trim_ows(&line);
            if s.is_empty() {
                out.push(
                    ctx.report_with(
                        &TOKEN_EMPTY,
                        "Access-Control-Request-Method names no method: `method = token` is \
                     `1*tchar` and this value has no characters"
                            .into(),
                    ),
                );
                continue;
            }
            if let Some(c) = crate::helpers::token::find_invalid_token_char(s) {
                out.push(ctx.report_with(
                    token_character(c),
                    format!(
                        "Access-Control-Request-Method '{}' contains {}, which is not a `tchar`, \
                         so it derives from no `token` and therefore from no `method`",
                        crate::helpers::shown::shown_in_finding(s),
                        crate::helpers::shown::describe_char(c)
                    ),
                ));
                continue;
            }
            // Asked only of a value that is a `method` to begin with: folding
            // something that derives from no `token` and comparing it against a
            // registry would be asking whether a value that is not a method is
            // the wrong sort of method.
            if crate::helpers::token::find_first_lowercase(s).is_some() {
                let folded = s.to_ascii_uppercase();
                if config.registered_methods.iter().any(|r| r == &folded) {
                    // The preflight announces the method a later request will
                    // use, and that comparison is byte-for-byte — § 9.1 says
                    // why the token is case-sensitive at all.
                    // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
                    out.push(ctx.report_with(
                        &METHOD_CASE_INVALID,
                        format!(
                            "Access-Control-Request-Method '{}' is '{folded}' written in another \
                             case. The method token is case-sensitive, so the preflight \
                             announces a method nothing defines",
                            crate::helpers::shown::shown_in_finding(s)
                        ),
                    ));
                }
            }
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CorsRequestHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cors_request_header_syntax",
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
            "cors_request_header_syntax".into(),
            toml::Value::Table(table),
        );
        cfg
    }

    fn run(headers: &[(&str, &str)]) -> Vec<Violation> {
        let rule = CorsRequestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
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

    #[rstest]
    #[case(&[("access-control-request-method", "POST")])]
    #[case(&[("access-control-request-headers", "Content-Type")])]
    #[case(&[("access-control-request-headers", "content-type,x-foo")])]
    #[case(&[("access-control-request-method", "PURGE")])]
    // No CORS fields at all: a request that is not a preflight.
    #[case(&[("accept", "*/*")])]
    fn a_conforming_request_draws_nothing(#[case] headers: &[(&str, &str)]) {
        assert_eq!(ids(headers), Vec::<String>::new(), "for {headers:?}");
    }

    #[rstest]
    #[case::acrh_space(
        &[("access-control-request-headers", "Content-Type X-Foo")],
        "token_whitespace_or_control_forbidden"
    )]
    #[case::acrh_colon(
        &[("access-control-request-headers", "Content-Type:")],
        "token_character_forbidden"
    )]
    #[case::acrh_gap(
        &[("access-control-request-headers", "X-Foo,,X-Baz")],
        "list_member_empty"
    )]
    #[case::acrh_empty(&[("access-control-request-headers", "")], "list_member_missing")]
    #[case::acrh_commas(&[("access-control-request-headers", ",,")], "list_member_missing")]
    #[case::acrm_paren(
        &[("access-control-request-method", "PO(ST")],
        "token_character_forbidden"
    )]
    #[case::acrm_space(
        &[("access-control-request-method", "PO ST")],
        "token_whitespace_or_control_forbidden"
    )]
    #[case::acrm_empty(&[("access-control-request-method", "")], "token_empty")]
    #[case::acrm_case(&[("access-control-request-method", "post")], "method_case_invalid")]
    fn each_defect_names_its_production(#[case] headers: &[(&str, &str)], #[case] expected: &str) {
        assert_eq!(ids(headers), vec![expected.to_string()], "for {headers:?}");
    }

    /// The one grammar difference across the ABNF block, asserted from both
    /// sides so a later edit cannot quietly make the two spellings agree:
    /// `1#field-name` has a floor and `#field-name` does not.
    #[test]
    fn the_request_lists_floor_is_not_the_response_lists() {
        assert_eq!(
            ids(&[("access-control-request-headers", "")]),
            vec!["list_member_missing".to_string()]
        );

        let rule = super::super::cors_response_header_syntax::CorsResponseHeaderSyntax;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cors_response_header_syntax",
        ]);
        let mut table = toml::map::Map::new();
        table.insert("enabled".into(), toml::Value::Boolean(true));
        table.insert(
            "registered_methods".into(),
            toml::Value::Array(vec![toml::Value::String("GET".into())]),
        );
        cfg.rules.insert(
            "cors_response_header_syntax".into(),
            toml::Value::Table(table),
        );
        let tx = crate::test_helpers::make_test_transaction_with_response(
            204,
            &[("access-control-expose-headers", "")],
        );
        assert!(crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_empty());
    }

    /// A value that derives from no `token` is not then asked whether it is a
    /// method spelled wrong.
    #[test]
    fn a_value_that_is_no_token_is_not_also_a_case_finding() {
        let v = run(&[("access-control-request-method", "po st")]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].violation, "token_whitespace_or_control_forbidden");
    }

    /// The convention is evidence and not a grammar.
    #[test]
    fn only_a_name_the_deployment_expects_draws_the_case_finding() {
        assert_eq!(
            ids(&[("access-control-request-method", "purge")]),
            Vec::<String>::new()
        );
    }

    /// Every offending member is answered, and each names itself.
    #[test]
    fn every_offending_member_is_reported() {
        let v = run(&[("access-control-request-headers", "X@Foo, Y@Bar")]);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v[0].message.contains("'X@Foo'"), "{}", v[0].message);
        assert!(v[1].message.contains("'Y@Bar'"), "{}", v[1].message);
    }

    /// Both fields are read on one request, and neither masks the other.
    #[test]
    fn the_two_fields_are_independent() {
        let v = run(&[
            ("access-control-request-method", "post"),
            ("access-control-request-headers", "X@Foo"),
        ]);
        let mut got: Vec<&str> = v.iter().map(|f| f.violation.as_str()).collect();
        got.sort_unstable();
        assert_eq!(
            got,
            vec!["method_case_invalid", "token_character_forbidden"]
        );
    }

    /// Findings are the client's: the preflight is what a user agent wrote.
    #[test]
    fn the_findings_are_the_clients() {
        let v = run(&[("access-control-request-method", "post")]);
        assert_eq!(v[0].party, Some(crate::lint::Party::Client), "{v:?}");
    }

    /// Request-only: the trait's one gate is `needs_response`, and a rule that
    /// reads a preflight has nothing to say about the answer.
    #[test]
    fn a_response_is_not_needed() {
        assert!(!CorsRequestHeaderSyntax.needs_response());
    }

    #[test]
    fn the_registered_methods_array_is_required() {
        let rule = CorsRequestHeaderSyntax;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".into(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cors_request_header_syntax".into(),
            toml::Value::Table(table),
        );
        assert!(rule.prepare(&cfg).is_err());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        CorsRequestHeaderSyntax.prepare(&cfg()).map(|_| ())
    }
}
