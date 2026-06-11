// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticOptionsMethodCapabilities;

impl Rule for SemanticOptionsMethodCapabilities {
    fn id(&self) -> &'static str {
        "semantic_options_method_capabilities"
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
        // Only care about OPTIONS requests with a final response
        if !tx.request.method.eq_ignore_ascii_case("OPTIONS") {
            return None;
        }

        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // RFC 9110 §9.3.7: "A server generating a successful response to OPTIONS
        // SHOULD send any header that might indicate optional features
        // implemented by the server and applicable to the target resource (e.g.,
        // Allow)".  We interpret "successful" as 2xx here.
        if !(200..300).contains(&resp.status) {
            return None;
        }

        if !resp.headers.contains_key("allow") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Successful OPTIONS response SHOULD include an Allow header".into(),
            });
        }

        None
    }

    fn description(&self) -> &'static str {
        "When a server responds to an `OPTIONS` request with a successful status code, it\nis expected to advertise the set of communication options supported for the\nselected resource.  An `Allow` header field is the canonical way to list the\nmethods that are allowed, and absence of the header hinders clients and\nintermediaries from discovering what operations are permitted.\n\nThis rule flags successful `OPTIONS` responses that omit the `Allow` header."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): OPTIONS method semantics (\"A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow)\").",
            "[RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): `Allow` header field definition.",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 204 No Content\nAllow: OPTIONS",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n# missing Allow header",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SemanticOptionsMethodCapabilities;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_opts_tx(
        status: u16,
        header: Option<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        use crate::test_helpers::make_test_transaction_with_response;
        let pairs = if let Some(h) = header {
            vec![h]
        } else {
            vec![]
        };
        let mut tx = make_test_transaction_with_response(status, &pairs);
        tx.request.method = "OPTIONS".into();
        tx
    }

    #[rstest]
    #[case(200, None, true)]
    #[case(200, Some(("allow", "GET, HEAD")), false)]
    #[case(204, None, true)]
    #[case(204, Some(("allow", "OPTIONS")), false)]
    #[case(201, None, true)]
    #[case(201, Some(("allow", "POST")), false)]
    #[case(404, None, false)]
    #[case(405, None, false)] // 405 handled by other rule
    fn options_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = SemanticOptionsMethodCapabilities;
        let tx = make_opts_tx(status, header);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for status {}", status);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for status {}: {:?}",
                status,
                v
            );
        }
    }

    #[test]
    fn violation_message_is_informative() {
        let rule = SemanticOptionsMethodCapabilities;
        let tx = make_opts_tx(200, None);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Allow"));
    }

    #[test]
    fn non_options_request_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_options_method_capabilities",
        ]);
        let v = SemanticOptionsMethodCapabilities.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = SemanticOptionsMethodCapabilities;
        assert_eq!(rule.id(), "semantic_options_method_capabilities");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn missing_response_is_ignored() {
        let rule = SemanticOptionsMethodCapabilities;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.response = None;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_none(),
            "expected no violation when no response is present"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_options_method_capabilities");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
