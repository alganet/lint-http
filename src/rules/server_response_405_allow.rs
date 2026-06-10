// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerResponse405Allow;

impl Rule for ServerResponse405Allow {
    fn id(&self) -> &'static str {
        "server_response_405_allow"
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
        if let Some(resp) = &tx.response {
            if resp.status == 405 && !resp.headers.contains_key("allow") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Response 405 without Allow header".into(),
                });
            }
        }
        None
    }

    fn description(&self) -> &'static str {
        "This rule checks if `405 Method Not Allowed` responses include an `Allow` header.\n\nThe `Allow` header is required in `405` responses to indicate the set of methods supported by the resource, so clients can discover what operations are permitted."
    }

    fn rfc_reference(&self) -> Option<&'static str> {
        Some("[RFC 9110 §10.5.6](https://www.rfc-editor.org/rfc/rfc9110.html#name-405-method-not-allowed): 405 Method Not Allowed")
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                snippet: "HTTP/1.1 405 Method Not Allowed\nContent-Type: text/plain\nAllow: GET, HEAD",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "HTTP/1.1 405 Method Not Allowed\nContent-Type: text/plain\n# Missing Allow header",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerResponse405Allow;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(405, None, true, Some("Response 405 without Allow header"))]
    #[case(405, Some(("allow", "GET, HEAD")), false, None)]
    #[case(200, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerResponse405Allow;

        use crate::test_helpers::make_test_transaction_with_response;
        let header_pairs: Vec<(&str, &str)> = match header {
            Some((k, v)) => vec![(k, v)],
            None => vec![],
        };
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }
}
