// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cross_origin::{CROSS_ORIGIN_OPENER_POLICY_INVALID, HTML_7_1_3_1};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::ViolationDef;

/// The one entry a field with no list form always has available: its own
/// repetition. The value on each line here is measured by the checks below;
/// what § 5.3 forbids is there being two lines at all.
static DECLARED: &[&ViolationDef] = &[&FIELD_LINE_DUPLICATED, &CROSS_ORIGIN_OPENER_POLICY_INVALID];

pub struct CrossOriginOpenerPolicyValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_CROSS_ORIGIN_OPENER_POLICY: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Cross-Origin-Opener-Policy",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy",
    note: "Cross-Origin-Opener-Policy",
};
const HTML: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML",
    section: None,
    url: "https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies",
    note: "“Cross-origin opener policies” — the possible opener policy values and their meanings",
};

impl RuleMeta for CrossOriginOpenerPolicyValid {
    fn id(&self) -> &'static str {
        "cross_origin_opener_policy_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Cross-Origin-Opener-Policy Value")
    }

    fn description(&self) -> &'static str {
        "This rule checks the `Cross-Origin-Opener-Policy` response header value and ensures it is one of the allowed tokens: **`same-origin`**, **`same-origin-allow-popups`**, **`noopener-allow-popups`**, or **`unsafe-none`**. The value is a structured-field token, compared as written — a browser reading `Same-Origin` ignores the header — and it may carry parameters, of which HTML names `report-to` for a reporting endpoint. The header must be a single value and must not contain comma-separated lists or multiple header fields. Note: `same-origin-plus-COEP` is an opener policy value, but the HTML Standard states it cannot be set directly through this header — it results from combining `same-origin` with a compatible `Cross-Origin-Embedder-Policy` — so a response carrying it is flagged. This header is response-only; the rule applies to server responses."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            MDN_CROSS_ORIGIN_OPENER_POLICY,
            HTML_7_1_3_1,
            HTML,
            RFC_9110_5_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(response)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: same-origin",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(with a reporting endpoint, and surrounding whitespace tolerated)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy:  same-origin-allow-popups; report-to=\"coop\"  ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a token is compared as written, and a browser ignores this one)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: SAME-ORIGIN-ALLOW-POPUPS",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unsupported value)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: other",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(comma-separated list)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: same-origin, unsafe-none",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields)"),
                snippet: "HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: same-origin\nCross-Origin-Opener-Policy: unsafe-none",
            },
        ]
    }
}

impl Rule for CrossOriginOpenerPolicyValid {
    fn needs_response(&self) -> bool {
        true
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
            // COOP is a response-only header per spec; ignore requests
            let resp = if let Some(resp) = &tx.response {
                resp
            } else {
                return None;
            };
            let headers = &resp.headers;

            let count = headers.get_all("cross-origin-opener-policy").iter().count();
            if count == 0 {
                return None;
            }

            if count > 1 {
                return Some(ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    "Multiple Cross-Origin-Opener-Policy header fields present".into(),
                ));
            }

            // Read as the octets the sender wrote. The value is a structured-field
            // item whose four accepted tokens are all inside visible US-ASCII, so
            // a value the string reader refuses is a value none of them spell —
            // which is what the finding below says, with the value in hand.
            let hv = headers
                .get_all("cross-origin-opener-policy")
                .iter()
                .next()
                .expect("a field line, since the count above is one");
            let line = crate::helpers::headers::field_line_as_written(hv);
            let val = crate::helpers::headers::trim_ows(&line);

            // Must not be a comma-separated list. The split respects quotes
            // because a parameter's String may hold a comma: `report-to="a,b"`
            // is one Item.
            if crate::helpers::structured_fields::split_commas_outside_quotes(val).len() != 1 {
                // Not a list defect: the field has no list form, so a comma
                // produces a value the item parse does not yield — which is the
                // same place a typo leaves the browsing context group.
                return Some(ctx.report_with(
                    &CROSS_ORIGIN_OPENER_POLICY_INVALID,
                    "Cross-Origin-Opener-Policy must be a single value".into(),
                ));
            }

            // The value is an Item: a token, and parameters after it. HTML
            // names one of them — `report-to`, the endpoint violations are sent
            // to — and the algorithm reads it, so a parameterized value is the
            // header as deployed rather than a longer spelling of a wrong one.
            // An Item that does not parse is ignored outright, and the context
            // gets `unsafe-none`, the policy the sender was writing the header
            // to leave.
            // cite(HTML § 7.1.3.1): "The token may also have attached parameters; of these, the "report-to" parameter can have a valid URL string identifying an appropriate reporting endpoint."
            // cite(HTML § 7.1.3.1): "Likewise, user agents will ignore this header if the value cannot be parsed as a token."
            if let Some(defect) = crate::helpers::structured_fields::parse_item(val) {
                return Some(ctx.report_with(
                    &CROSS_ORIGIN_OPENER_POLICY_INVALID,
                    format!(
                        "Cross-Origin-Opener-Policy '{}' does not parse as a structured-field item ({}), so a browser ignores it and the document gets 'unsafe-none'",
                        crate::helpers::shown::shown_in_finding(val),
                        defect.message
                    ),
                ));
            }
            let token = crate::helpers::headers::trim_ows(
                crate::helpers::structured_fields::split_semicolons_outside_quotes(val)[0],
            );

            // Compared byte for byte: the processing model asks whether the
            // token *is* "same-origin", and a Structured Field token keeps the
            // case it was written in, so `Same-Origin` parses and matches none
            // of the branches — the same place a typo leaves the context.
            // `same-origin-plus-COEP` is deliberately absent: the algorithm
            // produces it only from the `same-origin` token combined with a
            // compatible COEP, never from a token of its own, so a response
            // literally carrying it *is* wrong.
            // cite(HTML § 7.1.3.1): "Let parsedItem be the result of getting a structured field value given `Cross-Origin-Opener-Policy` and "item" from response's header list."
            // cite(HTML § 7.1.3.1): "Per the processing model described below, user agents will ignore this header if it contains an invalid value."
            if matches!(
                token,
                "same-origin"
                    | "same-origin-allow-popups"
                    | "noopener-allow-popups"
                    | "unsafe-none"
            ) {
                return None;
            }

            Some(ctx.report_with(
                &CROSS_ORIGIN_OPENER_POLICY_INVALID,
                format!(
                    "Cross-Origin-Opener-Policy token '{}' is none of the four a browser acts on ('same-origin', 'same-origin-allow-popups', 'noopener-allow-popups', 'unsafe-none', compared as written), so the header is ignored and the document gets 'unsafe-none'",
                    crate::helpers::shown::shown_in_finding(token)
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CrossOriginOpenerPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("same-origin"), false)]
    #[case(Some("same-origin-allow-popups"), false)]
    #[case(Some("noopener-allow-popups"), false)]
    #[case(Some("unsafe-none"), false)]
    #[case(Some(" same-origin "), false)]
    // invalid
    #[case(Some(" SAME-ORIGIN "), true)]
    #[case(Some(""), true)]
    #[case(Some("other"), true)]
    // A real opener policy value, but not one this header can carry: it results from
    // combining `same-origin` with a COEP header, and cannot be set directly.
    #[case(Some("same-origin-plus-COEP"), true)]
    #[case(Some("same-origin, unsafe-none"), true)]
    fn check_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = CrossOriginOpenerPolicyValid;
        let mut tx = make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("cross-origin-opener-policy", v)],
            );
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}', got none", val);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{:?}': got {:?}",
                val,
                v
            );
        }
    }

    /// HTML reads the header as a structured-field Item and asks whether its
    /// token *is* one of the four, so a parameter beside a known token is the
    /// deployed form — `report-to` is the one the algorithm reads — and a
    /// token in any other case is ignored. Every finding, with its id.
    #[rstest]
    #[case::report_to(r#"same-origin; report-to="coop""#, &[])]
    #[case::report_to_unspaced(r#"same-origin-allow-popups;report-to="gws""#, &[])]
    #[case::a_comma_inside_the_string(r#"unsafe-none; report-to="a,b""#, &[])]
    #[case::a_parameter_html_does_not_name("noopener-allow-popups; foo", &[])]
    #[case::miscased("Same-Origin", &["cross_origin_opener_policy_invalid"])]
    #[case::miscased_with_report_to(
        r#"SAME-ORIGIN; report-to="coop""#,
        &["cross_origin_opener_policy_invalid"]
    )]
    #[case::a_string_is_no_token(r#""same-origin""#, &["cross_origin_opener_policy_invalid"])]
    #[case::an_empty_parameter("same-origin;", &["cross_origin_opener_policy_invalid"])]
    #[case::a_parameter_with_no_value(
        "same-origin; report-to=",
        &["cross_origin_opener_policy_invalid"]
    )]
    fn the_value_is_the_item_html_parses(#[case] value: &str, #[case] expected: &[&str]) {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-opener-policy", value)],
        );
        let found: Vec<String> = crate::test_helpers::run_rule_all(
            &CrossOriginOpenerPolicyValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "cross_origin_opener_policy_valid",
            ]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        assert_eq!(found, expected, "{value}");
    }

    #[test]
    fn no_response_no_violation() {
        let rule = CrossOriginOpenerPolicyValid;
        let tx = make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_headers_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = CrossOriginOpenerPolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-opener-policy", "same-origin")]);
        hdrs.append(
            "cross-origin-opener-policy",
            HeaderValue::from_static("unsafe-none"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
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
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Multiple Cross-Origin-Opener-Policy"));
    }

    #[test]
    fn an_obs_text_octet_is_a_value_none_of_them_spell() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = CrossOriginOpenerPolicyValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("cross-origin-opener-policy", "same-origin")]);
        hdrs.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

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
        assert_eq!(
            v.expect("a finding").message,
            "Cross-Origin-Opener-Policy 'ÿ' does not parse as a structured-field item (invalid item 'ÿ'), so a browser ignores it and the document gets 'unsafe-none'"
        );
    }

    #[test]
    fn needs_a_response() {
        let rule = CrossOriginOpenerPolicyValid;
        assert!(rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CrossOriginOpenerPolicyValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cross_origin_opener_policy_valid".into(),
            toml::Value::Table(table),
        );

        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn trailing_whitespace_is_accepted() {
        let rule = CrossOriginOpenerPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-opener-policy", "same-origin ")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_value_reports_value() {
        let rule = CrossOriginOpenerPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-opener-policy", "other")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert!(v.message.contains("none of the four a browser acts on"));
        assert!(v.message.contains("'other'"));
    }

    #[test]
    fn comma_list_reports_single_value_message() {
        let rule = CrossOriginOpenerPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-opener-policy", "same-origin, unsafe-none")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap();
        assert!(v.message.contains("single value"));
    }

    #[test]
    fn allow_popups_trailing_whitespace_accepted() {
        let rule = CrossOriginOpenerPolicyValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cross-origin-opener-policy", " same-origin-allow-popups ")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }
}
