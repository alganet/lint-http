// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerCacheControlPresent;

impl Rule for ServerCacheControlPresent {
    fn id(&self) -> &'static str {
        "server_cache_control_present"
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
            if resp.status == 200 && !resp.headers.contains_key("cache-control") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Response 200 without Cache-Control header".into(),
                });
            }
        }
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Cache-Control Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if `200 OK` responses include a `Cache-Control` header.\n\nThe `Cache-Control` header is the primary mechanism for defining the caching policies of a resource. Even if a resource should not be cached, it is best practice to explicitly state this (e.g., `Cache-Control: no-store`) rather than relying on default browser behaviors or heuristic caching."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9111",
            section: Some("5.2"),
            url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2",
            note: "Cache-Control header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/json\nCache-Control: no-store",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/json\n# Missing Cache-Control header",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerCacheControlPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(200, None, true, Some("Response 200 without Cache-Control header"))]
    #[case(200, Some(("cache-control", "no-cache")), false, None)]
    #[case(404, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerCacheControlPresent;

        use crate::test_helpers::make_test_transaction_with_response;
        let tx = match header {
            Some((k, v)) => make_test_transaction_with_response(status, &[(k, v)]),
            None => make_test_transaction_with_response(status, &[]),
        };
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

    #[test]
    fn scope_is_server() {
        let rule = ServerCacheControlPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
