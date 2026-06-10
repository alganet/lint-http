// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestTargetNoFragment;

impl Rule for ClientRequestTargetNoFragment {
    fn id(&self) -> &'static str {
        "client_request_target_no_fragment"
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
        if tx.request.uri.contains('#') {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request-target MUST NOT include a URI fragment ('#')".into(),
            });
        }
        None
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestTargetNoFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("http://example.com/path", false)]
    #[case("/origin-form", false)]
    #[case("/origin-form?query", false)]
    #[case("http://example.com/path#fragment", true)]
    #[case("/origin-form#fragment", true)]
    #[case("#fragment-only", true)]
    fn check_request_target(#[case] uri: &str, #[case] expect_violation: bool) {
        let rule = ClientRequestTargetNoFragment;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "client_request_target_no_fragment");
            assert!(v.message.contains("'#'"));
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestTargetNoFragment;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
