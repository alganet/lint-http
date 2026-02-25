// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerStatusCodeValidRange;

impl Rule for ServerStatusCodeValidRange {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_status_code_valid_range"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };

        let status = resp.status;
        if !(100..=599).contains(&status) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "HTTP response status code {} is outside the valid range of 100-599 (RFC 9110 §15.1)",
                    status
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(200, false)]
    #[case(100, false)]
    #[case(599, false)]
    #[case(99, true)]
    #[case(600, true)]
    #[case(0, true)]
    #[case(1000, true)]
    fn check_status_range(#[case] status: u16, #[case] expect_violation: bool) {
        let rule = ServerStatusCodeValidRange;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
        });

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Error,
        };

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "server_status_code_valid_range");
            assert!(v.message.contains(&status.to_string()));
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn check_missing_response() {
        let rule = ServerStatusCodeValidRange;
        let tx = crate::test_helpers::make_test_transaction();

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Error,
        };

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }
}
