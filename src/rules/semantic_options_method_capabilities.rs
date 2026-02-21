// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticOptionsMethodCapabilities;

impl Rule for SemanticOptionsMethodCapabilities {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_options_method_capabilities"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
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
}

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
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("Allow"));
    }

    #[test]
    fn non_options_request_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = SemanticOptionsMethodCapabilities.check_transaction(&tx, None, &cfg);
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
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_none(),
            "expected no violation when no response is present"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_options_method_capabilities");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
