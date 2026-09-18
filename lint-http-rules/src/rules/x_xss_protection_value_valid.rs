// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::x_xss_protection::X_XSS_PROTECTION_INVALID;
use crate::violations::ViolationDef;

/// The field's one value entry, and the entry a field with no list form always
/// has available — its own repetition. What § 5.3 forbids is there being two
/// lines at all; whether the one line asks for the filter off is the other
/// entry's business, and it names no document because nothing ever defined
/// this field.
static DECLARED: &[&ViolationDef] = &[&FIELD_LINE_DUPLICATED, &X_XSS_PROTECTION_INVALID];

pub struct XXssProtectionValueValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_X_XSS_PROTECTION: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN X-XSS-Protection",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection",
    note: "X-XSS-Protection",
};
const OWASP_SECURE_HEADERS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "OWASP Secure Headers",
    section: None,
    url: "https://owasp.org/www-project-secure-headers/",
    note: "OWASP guidance",
};

impl RuleMeta for XXssProtectionValueValid {
    fn id(&self) -> &'static str {
        "x_xss_protection_value_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server X-XSS-Protection Value Valid")
    }

    fn description(&self) -> &'static str {
        "This rule checks that the `X-XSS-Protection` response header, when present, uses an expected and safe value. Historically, the header accepted `0` to disable the browser's cross-site scripting filter and `1; mode=block` to enable blocking; other values are unsupported or ambiguous and should be avoided."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[MDN_X_XSS_PROTECTION, OWASP_SECURE_HEADERS, RFC_9110_5_3]
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
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 1; mode=block",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 2",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 1; report=1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`mode=block` beside a setting no reference defines with it)"),
                snippet: "HTTP/1.1 200 OK\nX-XSS-Protection: 1; mode=block; report=/r",
            },
        ]
    }
}

impl Rule for XXssProtectionValueValid {
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
            // A response header (a legacy browser feature; no standard ever defined it),
            // so only the response side is inspected. Its absence is fine — CSP is the
            // replacement — which is why count == 0 simply passes.
            // cite(MDN X-XSS-Protection): "response header was a feature of Internet Explorer, Chrome and Safari that stopped pages from loading when they detected reflected cross-site scripting"
            let resp = tx.response.as_ref()?;

            let headers = &resp.headers;
            let count = headers.get_all("x-xss-protection").iter().count();
            if count == 0 {
                return None;
            }

            // The value was never defined as a comma-separated list, so a sender may
            // not repeat the field.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    "Multiple X-XSS-Protection header fields present".into(),
                ));
            }

            // Read as the octets the sender wrote. Every spelling this rule
            // accepts is inside visible US-ASCII, so a value the string reader
            // refuses is a value none of them spell — which the unsupported-value
            // finding at the end says, and it can quote what arrived.
            let hv = headers
                .get_all("x-xss-protection")
                .iter()
                .next()
                .expect("a field line, since the count above is one");
            let line = crate::helpers::headers::field_line_as_written(hv);
            let val = crate::helpers::headers::trim_ows(&line);

            // Accept exactly "0" or "1;mode=block" (allow whitespace around separators, case-insensitive)
            // `1` and `1; report=<uri>` are documented values that this rule reports anyway,
            // and the description is what draws that line rather than a grammar: those two
            // ask the filter to rewrite the page, which is the behaviour the warning is about,
            // and the same description names the pair that does not rewrite it.
            // cite(MDN X-XSS-Protection): "Even though this feature can protect users of older web browsers that don't support CSP, in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites."
            // cite(MDN X-XSS-Protection): "Disables XSS filtering."
            if val.eq_ignore_ascii_case("0") {
                return None;
            }

            // Split on ';' and validate structure: exactly two parts, first is '1', second is 'mode=block'
            // cite(MDN X-XSS-Protection): "Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected."
            let parts: Vec<&str> = val
                .split(';')
                .map(crate::helpers::headers::trim_ows)
                .collect();
            if parts.len() == 2
                && parts[0].eq_ignore_ascii_case("1")
                && parts[1].eq_ignore_ascii_case("mode=block")
            {
                return None;
            }

            // A value that spells the blocking pair and then keeps going. It is
            // still reported — no document defines `mode=block` beside a further
            // setting, so which behaviour a browser applies is not something any
            // reference here states — but the sentence below cannot be the one
            // that says it. "Neither of the two settings that keep the browser
            // from rewriting the page" is a claim about the octets, and
            // `mode=block` is written in them: a deployment that had already
            // chosen the blocking spelling was told it had not. What is unknown
            // is the combination, and that is what the finding now says.
            let spells_block = parts[0].eq_ignore_ascii_case("1")
                && parts[1..]
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case("mode=block"));
            // A trailing `;` leaves an empty part and adds no setting, so it is
            // not what this branch is about: `1;mode=block;` is still the pair
            // and nothing else, and the sentence below stays its answer.
            let further = parts[1..]
                .iter()
                .any(|p| !p.is_empty() && !p.eq_ignore_ascii_case("mode=block"));
            if spells_block && further {
                return Some(ctx.report_with(
                    &X_XSS_PROTECTION_INVALID,
                    format!(
                        "X-XSS-Protection is set to '{}', which spells '1; mode=block' and then a further setting that no reference here defines beside it, so which behaviour a browser applies is unstated: '0' turns the filter off, and '1; mode=block' on its own has the page blocked instead of sanitized",
                        crate::helpers::shown::shown_in_finding(val)
                    ),
                ));
            }

            // Naming the two settings rather than calling the value unsupported. A
            // bare `1` and `1; report=<uri>` are in the description's own syntax
            // list, so "unsupported" would be false of them — and an operator told
            // that has no way to see that the repair is either of the two spellings
            // below, one of which is not the value they already wrote.
            Some(ctx.report_with(
                &X_XSS_PROTECTION_INVALID,
                format!(
                    "X-XSS-Protection is set to '{}', which is neither of the two settings that keep the browser from rewriting the page: '0' turns the filter off, and '1; mode=block' has the page blocked instead of sanitized",
                    crate::helpers::shown::shown_in_finding(val)
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &XXssProtectionValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("0"), false)]
    #[case(Some("0 "), false)]
    #[case(Some("1;mode=block"), false)]
    #[case(Some("1; mode=block"), false)]
    #[case(Some("1;MODE=BLOCK"), false)]
    #[case(Some("1;  mode=block  "), false)]
    // values that ask the browser to rewrite the page, or that are no setting
    // at all. `1; mode=block; report=<uri>` is here because a deployment does
    // send it: the description spells `mode=block` and `report=` as two
    // separate settings and never the pair, so which of them a browser would
    // honour is not something any document here says.
    #[case(Some("1"), true)]
    #[case(Some("2"), true)]
    #[case(Some("1;report=1"), true)]
    #[case(Some("1; mode=none"), true)]
    #[case(Some("1; mode=block; report=https://example.test/r"), true)]
    #[case(Some(""), true)]
    fn check_header_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = XXssProtectionValueValid;
        let mut tx = make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("x-xss-protection", v)],
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
                "did not expect violation for '{:?}', got {:?}",
                val,
                v
            );
        }
    }

    /// One id for both kinds of value the rule declines — the setting the
    /// field never had, and the two it did have and this crate refuses — and
    /// `info`, because nothing in force refuses either of them.
    #[rstest]
    #[case("2")]
    #[case("1")]
    #[case("1;report=1")]
    #[case("1; mode=block; report=/r")]
    fn every_declined_value_reports_one_entry_at_the_rank_of_advice(#[case] value: &str) {
        let rule = XXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", value)],
        );
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "x_xss_protection_invalid", "{value}");
        assert_eq!(found.severity, crate::lint::Severity::Info, "{value}");
    }

    /// A value carrying `mode=block` is not told it carries neither setting.
    /// The finding stands — nothing defines the pair beside a further setting
    /// — but the sentence has to be true of the octets, and four deployments
    /// that had already chosen the blocking spelling were reading that they
    /// had not.
    #[test]
    fn a_value_spelling_mode_block_is_not_told_it_spells_neither_setting() {
        let rule = XXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "x-xss-protection",
                "1; mode=block; report=https://example.test/r",
            )],
        );
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert!(
            !found.message.contains("neither of the two settings"),
            "{}",
            found.message
        );
        assert!(found.message.contains("unstated"), "{}", found.message);

        // The values that genuinely spell neither keep the sentence that says so.
        for bare in ["1", "1;report=1", "2"] {
            let tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("x-xss-protection", bare)],
            );
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("a finding");
            assert!(
                found.message.contains("neither of the two settings"),
                "{bare}: {}",
                found.message
            );
        }
    }

    #[test]
    fn multiple_headers_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = XXssProtectionValueValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("x-xss-protection", "0")]);
        hdrs.append("x-xss-protection", HeaderValue::from_static("1;mode=block"));
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
        assert!(v.unwrap().message.contains("Multiple X-XSS-Protection"));
    }

    #[test]
    fn an_obs_text_octet_is_a_value_none_of_them_spell() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = XXssProtectionValueValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("x-xss-protection", "0")]);
        hdrs.insert(
            "x-xss-protection",
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
        assert!(v
            .expect("a finding")
            .message
            .starts_with("X-XSS-Protection is set to 'ÿ', which is neither"));
    }

    #[test]
    fn needs_a_response() {
        let rule = XXssProtectionValueValid;
        assert!(rule.needs_response());
    }

    #[test]
    fn no_response_returns_none() {
        let rule = XXssProtectionValueValid;
        let tx = make_test_transaction(); // no response set
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_without_header_returns_none() {
        let rule = XXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The repair, held where the message is built. A bare `1` and
    /// `1; report=<uri>` are spellings the description lists, so a finding may
    /// not call them unsupported; what it may say is that neither keeps the
    /// browser from rewriting the page, and it has to name the two that do —
    /// otherwise the reader is left to guess, and the nearest guess from `1` is
    /// the value they already wrote.
    #[rstest]
    #[case("1")]
    #[case("1; report=https://example.test/r")]
    #[case("1; mode=block; report=https://example.test/r")]
    #[case("2")]
    fn the_message_quotes_the_value_and_names_both_settings_that_repair_it(#[case] value: &str) {
        let rule = XXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", value)],
        );
        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding")
        .message;
        assert!(msg.contains(value), "the value it fired on: {msg}");
        assert!(msg.contains("'0'"), "the setting that turns it off: {msg}");
        assert!(
            msg.contains("'1; mode=block'"),
            "the setting that blocks instead of sanitizing: {msg}"
        );
        assert!(
            !msg.contains("unsupported"),
            "a spelling the description lists is not unsupported: {msg}"
        );
    }

    #[test]
    fn extra_semicolon_is_violation_and_reported() {
        let rule = XXssProtectionValueValid;
        let val = "1;mode=block;";
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("neither of the two settings") && m.contains(val));
    }

    #[test]
    fn comma_separated_values_are_violation() {
        let rule = XXssProtectionValueValid;
        let val = "0, 1;mode=block";
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", val)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("neither of the two settings") && m.contains("0, 1;mode=block"));
    }
}
