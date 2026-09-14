// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::access_control_allow_origin::{
    ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY, ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED, FETCH_3_3_3,
};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::ViolationDef;

/// The field's two findings, plus the one a field with no list form always has
/// available: its own repetition.
static DECLARED: &[&ViolationDef] = &[
    &ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY,
    &ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED,
    &FIELD_LINE_DUPLICATED,
];

pub struct AccessControlAllowOriginValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_ACCESS_CONTROL_ALLOW_ORIGIN: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Access-Control-Allow-Origin",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin",
    note: "Access-Control-Allow-Origin",
};
const FETCH_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.2"),
    url: "https://fetch.spec.whatwg.org/#origin-header",
    note: "Governing origin syntax: `serialized-origin` ends at its authority, so a path (not even a trailing slash), a query or a fragment all disqualify it; the host inside it is a `reg-name` or a bracketed `IP-literal`, so a character outside those productions or a malformed percent-encoding disqualifies it too; and `origin-or-null`'s `null` is case-sensitive",
};
const RFC_6454_7_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6454",
    section: Some("7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1",
    note: "Historical origin syntax the non-`*` value is validated against — `serialized-origin = scheme \"://\" host [ \":\" port ]`, and `null` via origin-list-or-null; Fetch §3.2 supplants it",
};

impl RuleMeta for AccessControlAllowOriginValid {
    fn id(&self) -> &'static str {
        "access_control_allow_origin_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Access-Control-Allow-Origin Syntax")
    }

    fn description(&self) -> &'static str {
        "This rule checks that the `Access-Control-Allow-Origin` response header is syntactically valid: it must be a single value and that value must be either `*`, `null`, or a valid serialized-origin (scheme://host[:port]).\n\nThe field has no list form, so a comma-separated value is not a broken list — it is a value the CORS check's byte comparison matches against no origin at all, which is what a bare host such as `example.com` is too. Both are reported as the same defect, and the message names the shape that arrived.\n\nA line written with nothing on it is reported separately: that sender meant to state an origin and stated none. Repeated field lines are the field-order defect twenty other fields report."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            MDN_ACCESS_CONTROL_ALLOW_ORIGIN,
            FETCH_3_3_3,
            FETCH_3_2,
            RFC_6454_7_1,
            RFC_9110_5_3,
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
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: null",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a, https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a\nAccess-Control-Allow-Origin: https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a serialized origin has no path, not even a trailing slash"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com/",
            },
        ]
    }
}

impl Rule for AccessControlAllowOriginValid {
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
            let resp = tx.response.as_ref()?;

            let headers = &resp.headers;

            let acao_count = headers
                .get_all("access-control-allow-origin")
                .iter()
                .count();
            if acao_count == 0 {
                return None;
            }

            // Multiple header fields are not allowed for Access-Control-Allow-Origin: the
            // header carries one value — an echoed origin, `null`, or `*` — not a list.
            // cite(Fetch § 3.3.3): "Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response."
            if acao_count > 1 {
                return Some(ctx.report_with(&FIELD_LINE_DUPLICATED, "Multiple Access-Control-Allow-Origin header fields present; only a single value ('*' or a single origin) is allowed".into()));
            }

            // There is a single header field; validate its single value semantics and origin syntax.
            let hv = headers
                .get_all("access-control-allow-origin")
                .iter()
                .next()
                .unwrap();
            // Read as the octets the sender wrote. The value derives from one of
            // three alternatives — `*`, the case-sensitive `null`, or a
            // serialized origin — and every one of them is inside visible
            // US-ASCII, so an octet above it is a value deriving from none of
            // them and the finding below says exactly that. Naming the octet
            // class instead was a fourth verdict for a value that had already
            // failed all three.
            let line = crate::helpers::headers::field_line_as_written(hv);
            let s = crate::helpers::headers::trim_ows(&line);

            // Must be a single value (not a comma-separated list). The two
            // arms are one defect and two senders: a line with nothing on it
            // (or nothing but commas) is a server that meant to state an origin
            // and stated none, and a line with two members is a server that
            // stated one the byte comparison below will match against nothing.
            let members: Vec<String> = crate::helpers::list::list_members(s)
                .map(|m| m.to_string())
                .collect();
            if members.is_empty() {
                return Some(ctx.report(&ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY));
            }
            if members.len() > 1 {
                return Some(ctx.report_with(
                    &ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED,
                    format!(
                        "Access-Control-Allow-Origin is '{}', which holds {} comma-separated members: the field carries a single value ('*', 'null', or a serialized origin) and has no list form",
                        crate::helpers::shown::shown_in_finding(s),
                        members.len(),
                    ),
                ));
            }

            let member = members.into_iter().next().unwrap();
            if member == "*" || member == "null" {
                return None;
            }

            if !crate::helpers::uri::is_valid_serialized_origin(&member) {
                return Some(ctx.report_with(
                    &ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED,
                    format!(
                        "Access-Control-Allow-Origin contains invalid origin: '{}'",
                        crate::helpers::shown::shown_in_finding(&member)
                    ),
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AccessControlAllowOriginValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[test]
    fn no_response_no_violation() {
        let rule = AccessControlAllowOriginValid;
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
    fn response_without_acao_header_returns_none() {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    #[case("*")]
    #[case("null")]
    #[case("https://example.com")]
    #[case("  https://example.com  ")]
    // A port is a 16-bit unsigned integer and `0` is one of them — reserved at
    // the edge of a range rather than invalid. The shared origin reader rejected
    // it until the port reading was shared with the two rules that had audited
    // the bound, so this value drew a finding naming an origin that is one.
    #[case("https://example.com:0")]
    #[case("https://example.com:65535")]
    fn valid_single_values(#[case] val: &str) {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "expected no violation for '{}': got {:?}",
            val,
            v
        );
    }

    // § 3.2 terminates an authority at "/", "?" or "#", and a serialized origin
    // ends where its authority does. Only the first of the three reached this
    // rule until the shared validator stopped enumerating them by hand.
    #[rstest]
    #[case("https://example.com/")]
    #[case("https://example.com/path")]
    #[case("https://example.com?x=1")]
    #[case("https://example.com#frag")]
    // The authority's *contents*, which the check measured nothing of: none of
    // these characters is in any `reg-name`, and a `%zz` is no `pct-encoded`.
    #[case("https://exa|mple.com")]
    #[case("https://a<b>c")]
    #[case("https://a^b")]
    #[case("https://a%zzb")]
    #[case("https://[foo]")]
    fn origin_with_anything_after_the_authority_is_violation(#[case] val: &str) {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.unwrap_or_else(|| panic!("expected violation for '{}'", val));
        assert!(v.message.contains("invalid origin"));
    }

    #[test]
    fn uppercase_null_is_violation() {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "NULL")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    /// The two findings the field's own subject holds, and the line between
    /// them: a value was written, or it was not. Everything on the wrong side
    /// of that line is one id however it is wrong — the field has no list form,
    /// so a comma produces a value the CORS check matches against nothing,
    /// exactly as a bare host does.
    #[rstest]
    #[case::blank("", "access_control_allow_origin_empty")]
    #[case::only_commas(",,", "access_control_allow_origin_empty")]
    #[case::two_members("https://a, https://b", "access_control_allow_origin_malformed")]
    #[case::no_scheme("example.com", "access_control_allow_origin_malformed")]
    #[case::uppercase_null("NULL", "access_control_allow_origin_malformed")]
    fn each_finding_of_the_field_names_its_entry(#[case] value: &str, #[case] id: &str) {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", value)],
        );
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("a finding for {value:?}"));
        assert_eq!(found.violation, id, "{value:?}");
    }

    /// The id is shared with the bare host above, so the message is what tells
    /// the two apart: it names the whole value and how many members were cut
    /// out of it, which is the fact a sender needs and the one the id cannot
    /// carry.
    #[test]
    fn a_comma_separated_value_says_how_many_members_arrived() {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://a, https://b")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let message = v.expect("a finding").message;
        assert!(message.contains("'https://a, https://b'"), "{message}");
        assert!(message.contains("2 comma-separated members"), "{message}");
        assert!(message.contains("single value"), "{message}");
    }

    #[test]
    fn multiple_header_fields_are_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = AccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.append(
            "access-control-allow-origin",
            HeaderValue::from_static("https://b"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

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
        assert_eq!(v.violation, "field_line_duplicated");
        assert!(v.message.contains("Multiple"));
    }

    #[test]
    fn invalid_origin_is_violation() {
        let rule = AccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "example.com")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    /// The octet is a value deriving from none of the three alternatives, and
    /// that is what the finding says. It used to be a fourth verdict — the octet
    /// class, named before the value had been measured against `*`, `null` or an
    /// origin — and the three-way alternation had already refused it.
    #[test]
    fn an_octet_is_a_value_deriving_from_none_of_the_alternatives() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = AccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

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
        assert!(v.message.contains("invalid origin"), "{}", v.message);
    }

    #[test]
    fn scope_is_server() {
        let rule = AccessControlAllowOriginValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = AccessControlAllowOriginValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "access_control_allow_origin_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }
}
