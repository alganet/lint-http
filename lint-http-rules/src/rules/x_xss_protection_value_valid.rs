// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct XXssProtectionValueValid;

impl Rule for XXssProtectionValueValid {
    fn id(&self) -> &'static str {
        "x_xss_protection_value_valid"
    }

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
                return Some(self.violation(
                    ctx.severity,
                    "Multiple X-XSS-Protection header fields present".into(),
                ));
            }

            // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
            let val = match crate::helpers::headers::get_header_str(headers, "x-xss-protection") {
                Some(v) => v.trim(),
                None => {
                    return Some(self.violation(
                        ctx.severity,
                        "X-XSS-Protection header contains non-ASCII or control characters".into(),
                    ))
                }
            };

            // Accept exactly "0" or "1;mode=block" (allow whitespace around separators, case-insensitive)
            // `1` and `1; report=<uri>` are documented values that this rule rejects anyway.
            // That is a policy, not a reading of a grammar: the filter these values enable is
            // the thing the quote below warns about, and `0` is the one safe setting.
            // cite(MDN X-XSS-Protection): "Even though this feature can protect users of older web browsers that don't support CSP, in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites."
            // cite(MDN X-XSS-Protection): "Disables XSS filtering."
            if val.eq_ignore_ascii_case("0") {
                return None;
            }

            // Split on ';' and validate structure: exactly two parts, first is '1', second is 'mode=block'
            // cite(MDN X-XSS-Protection): "Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected."
            let parts: Vec<&str> = val.split(';').map(|s| s.trim()).collect();
            if parts.len() == 2
                && parts[0].eq_ignore_ascii_case("1")
                && parts[1].eq_ignore_ascii_case("mode=block")
            {
                return None;
            }

            Some(self.violation(
                ctx.severity,
                format!("X-XSS-Protection contains unsupported value: '{}'", val),
            ))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server X-XSS-Protection Value Valid")
    }

    fn description(&self) -> &'static str {
        "This rule checks that the `X-XSS-Protection` response header, when present, uses an expected and safe value. Historically, the header accepted `0` to disable the browser's cross-site scripting filter and `1; mode=block` to enable blocking; other values are unsupported or ambiguous and should be avoided."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "MDN X-XSS-Protection",
                section: None,
                url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection",
                note: "X-XSS-Protection",
            },
            crate::rules::SpecRef {
                spec: "OWASP Secure Headers",
                section: None,
                url: "https://owasp.org/www-project-secure-headers/",
                note: "OWASP guidance",
            },
        ]
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
        ]
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
    // invalid values
    #[case(Some("1"), true)]
    #[case(Some("2"), true)]
    #[case(Some("1;report=1"), true)]
    #[case(Some("1; mode=none"), true)]
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
    fn non_utf8_header_value_is_violation() {
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
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn scope_is_server() {
        let rule = XXssProtectionValueValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
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

    #[test]
    fn unsupported_value_message_contains_value() {
        let rule = XXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", "1")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("1"));
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
        assert!(m.contains("unsupported value") && m.contains(val));
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
        assert!(m.contains("unsupported value") && m.contains("0, 1;mode=block"));
    }
}
