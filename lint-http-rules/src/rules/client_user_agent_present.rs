// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientUserAgentPresent;

impl Rule for ClientUserAgentPresent {
    fn id(&self) -> &'static str {
        "client_user_agent_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        if !tx.request.headers.contains_key("user-agent") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing User-Agent header".into(),
            })
        } else {
            None
        }
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client User-Agent Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if the client sends a `User-Agent` header in the request.\n\nWhile not strictly mandatory for all HTTP requests, the `User-Agent` header is highly recommended for identifying the client software, version, and operating system. It helps servers tailor responses and administrators debug issues."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("10.1.5"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
            note: "User-Agent header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "GET /api/data HTTP/1.1\nHost: example.com\nUser-Agent: MyClient/1.0 (Linux; x64)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "GET /api/data HTTP/1.1\nHost: example.com\nAccept: application/json",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientUserAgentPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(vec![], true, Some("Request missing User-Agent header"))]
    #[case(vec![("user-agent", "curl/7.68.0")], false, None)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ClientUserAgentPresent;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&header_pairs);
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
    fn scope_is_client() {
        let rule = ClientUserAgentPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
