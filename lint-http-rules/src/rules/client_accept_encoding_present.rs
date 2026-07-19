// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
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
        if !tx.request.headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing Accept-Encoding header".into(),
            })
        } else {
            None
        }
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Accept-Encoding Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if the client sends an `Accept-Encoding` header in the request.\n\nModern HTTP clients should support compression (gzip, brotli, etc.) to reduce bandwidth usage and improve performance. Omitting this header usually implies the client does not support compression, or it was manually disabled."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("12.5.3"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
            note: "Accept-Encoding header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet:
                    "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, deflate, br",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nUser-Agent: my-script/1.0",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientAcceptEncodingPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn check_request_accept_encoding_header(#[case] header_present: bool) -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let tx = if header_present {
            crate::test_helpers::make_test_transaction_with_headers(&[("accept-encoding", "gzip")])
        } else {
            crate::test_helpers::make_test_transaction()
        };
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if header_present {
            assert!(violation.is_none());
        } else {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                Some("Request missing Accept-Encoding header".to_string())
            );
        }
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientAcceptEncodingPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
