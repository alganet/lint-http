// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Accept-Ranges` should be either `bytes` or `none` (or absent).
/// Multiple values are allowed but MUST only contain `bytes`, and `none` must not be combined with other values.
pub struct ServerAcceptRangesValuesValid;

impl Rule for ServerAcceptRangesValuesValid {
    fn id(&self) -> &'static str {
        "server_accept_ranges_values_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        let val = crate::helpers::headers::get_header_str(&resp.headers, "accept-ranges")?;

        let mut saw_none = false;
        for token in crate::helpers::headers::parse_list_header(val) {
            // validate token characters
            if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Accept-Ranges contains invalid token character: '{}'", c),
                });
            }

            let t = token.to_ascii_lowercase();
            if t == "none" {
                saw_none = true;
            } else if t == "bytes" {
                // ok
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Accept-Ranges contains unexpected range-unit: '{}'", token),
                });
            }
        }

        // 'none' must be alone
        if saw_none {
            // If there is more than just 'none', that's invalid. Check by splitting and counting effective tokens.
            let count = crate::helpers::headers::parse_list_header(val).count();
            if count > 1 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Accept-Ranges: 'none' must not be combined with other range-units"
                        .into(),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Accept-Ranges Values Valid")
    }

    fn description(&self) -> &'static str {
        "Validate the `Accept-Ranges` response header. This rule enforces that:\n\n- When present, `Accept-Ranges` MUST contain only registered `range-unit` tokens.\n- For practical compatibility, this rule accepts `bytes` (the common range-unit) or `none` only.\n- The `none` token MUST NOT be combined with other range-units."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("7.3.4"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.4",
            note: "Accept-Ranges header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Accept-Ranges: bytes\nAccept-Ranges: none\nAccept-Ranges: bytes, bytes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Accept-Ranges: none, bytes\nAccept-Ranges: foobar\nAccept-Ranges: b ytes",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerAcceptRangesValuesValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(None, false)]
    #[case(Some("bytes"), false)]
    #[case(Some("none"), false)]
    #[case(Some("bytes, bytes"), false)]
    #[case(Some("BYTES"), false)]
    #[case(Some("none, bytes"), true)]
    #[case(Some("foo"), true)]
    #[case(Some("b ytes"), true)]
    fn accept_ranges_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerAcceptRangesValuesValid;
        let tx = match header {
            Some(h) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("accept-ranges", h)],
            ),
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_accept_ranges_values_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
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
    fn scope_is_server() {
        let rule = ServerAcceptRangesValuesValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn missing_response_returns_none() {
        let rule = ServerAcceptRangesValuesValid;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_accept_ranges_values_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
