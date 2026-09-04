// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// `Sec-Fetch-Mode` header must be one of the canonical values listed in
/// the Fetch Metadata spec: `cors`, `no-cors`, `same-origin`, `navigate`, or `websocket`.
/// The match is exact: modes are lowercase tokens and the structured-field
/// token carries no case folding; token syntax is validated.
pub struct SecFetchModeValueValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const FETCH_METADATA_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
spec: "Fetch Metadata",
section: Some("2.2"),
url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-mode-header",
note: "Fetch Metadata (W3C) — `Sec-Fetch-Mode`: an sf-token whose valid values are the five request modes",
        };

impl RuleMeta for SecFetchModeValueValid {
    fn id(&self) -> &'static str {
        "sec_fetch_mode_value_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Requests that include the `Sec-Fetch-Mode` request header must use one of the canonical values defined by the Fetch Metadata specification: `cors`, `no-cors`, `same-origin`, `navigate`, or `websocket`. This rule validates the header token syntax and that the value is exactly one of the accepted identifiers — modes are lowercase tokens and structured-field tokens carry no case folding, so `CORS` is not a valid value. Multiple header fields (repeated `Sec-Fetch-Mode`) are treated as a violation (possible header injection) and will be flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[FETCH_METADATA_2_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-Mode: cors",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-Mode: navigate",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-Mode: invalid",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-Mode:",
            },
        ]
    }
}

impl Rule for SecFetchModeValueValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            // Sec-Fetch-* are request-sent headers; check only requests
            // cite(Fetch Metadata § 2.2): "HTTP request header exposes a request’s mode to a server"
            let headers = &tx.request.headers;
            let count = headers.get_all("sec-fetch-mode").iter().count();
            if count == 0 {
                return None;
            }

            // A single structured-field item, never a list, so a sender may not repeat
            // the field.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(self.violation(
                    ctx.severity,
                    "Multiple Sec-Fetch-Mode header fields present".into(),
                ));
            }

            // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
            let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-mode") {
                Some(v) => v.trim(),
                None => {
                    return Some(self.violation(
                        ctx.severity,
                        "Sec-Fetch-Mode header contains non-ASCII or control characters".into(),
                    ))
                }
            };

            // An empty value cannot be a token.
            // cite(Fetch Metadata § 2.1): "It is a Structured Field whose value MUST be a token."
            if val.is_empty() {
                return Some(self.violation(ctx.severity, "Sec-Fetch-Mode header is empty".into()));
            }

            // Token must not contain invalid token chars. This checks the HTTP `token`
            // grammar, slightly looser than sf-token; the closed value match below is
            // what actually gates acceptance, so the difference only picks which
            // message a bad value gets.
            // cite(Fetch Metadata § 2.1): "It is a Structured Field whose value MUST be a token."
            if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                return Some(self.violation(
                    ctx.severity,
                    format!(
                        "Sec-Fetch-Mode header contains invalid token character: '{}'",
                        c
                    ),
                ));
            }

            // The spec tells servers to ignore unknown values for forward compatibility;
            // this rule lints the sender, where an unknown value means a non-conforming
            // (or non-browser) origin of the header, so it flags instead.
            // cite(Fetch Metadata § 2.1): "In order to support forward-compatibility with as-yet-unknown request types, servers SHOULD ignore this header if it contains an invalid value."
            // cite(Fetch Metadata § 2.2): "Valid Sec-Fetch-Mode values include "cors", "navigate", "no-cors", "same-origin", and "websocket"."
            match val {
                "cors" | "no-cors" | "same-origin" | "navigate" | "websocket" => None,
                _ => Some(self.violation(
                    ctx.severity,
                    format!("Unrecognized Sec-Fetch-Mode value: '{}'", val),
                )),
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecFetchModeValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("cors"), false)]
    #[case(Some("no-cors"), false)]
    #[case(Some("same-origin"), false)]
    #[case(Some("navigate"), false)]
    #[case(Some("websocket"), false)]
    #[case(Some("CORS"), true)] // modes are lowercase; the match is exact
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_mode_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn non_utf8_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchModeValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-mode", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", "b@d")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("cors"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("invalid"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn multiple_header_fields_both_valid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("cors"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("navigate"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("bad1"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("bad2"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = SecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_mode_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", " same-origin ")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn message_and_id() {
        let rule = SecFetchModeValueValid;
        assert_eq!(rule.id(), "sec_fetch_mode_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_fetch_mode_value_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
