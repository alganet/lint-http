// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Detects repeated 401 challenges for the same protection space (origin),
/// which indicates an authentication failure loop.
pub struct StatefulAuthenticationFailureLoop;

impl Rule for StatefulAuthenticationFailureLoop {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_authentication_failure_loop"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;
        if resp.status != 401 {
            return None;
        }

        let mut consecutive_401s = 0;

        for prev_tx in history.iter() {
            if let Some(prev_resp) = &prev_tx.response {
                if prev_resp.status == 401 {
                    consecutive_401s += 1;
                } else {
                    // Break on first non-401 response for this origin
                    break;
                }
            }
        }

        // We consider it a loop if there are more than 3 consecutive 401s *before* this one
        if consecutive_401s >= 3 {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Authentication failure loop detected: client has received {} consecutive 401 Unauthorized challenges for this origin.",
                    consecutive_401s + 1
                ),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_loop_detected() {
        let rule = StatefulAuthenticationFailureLoop;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.request.uri = "https://example.com/protected".to_string();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx1.request.uri = "https://example.com/login".to_string();

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx2.request.uri = "https://example.com/api".to_string();

        let mut tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx3.request.uri = "https://example.com/admin".to_string();

        let history = crate::transaction_history::TransactionHistory::new(vec![tx1, tx2, tx3]);

        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("4 consecutive"));
    }

    #[test]
    fn test_auth_loop_broken_by_200() {
        let rule = StatefulAuthenticationFailureLoop;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        let history = crate::transaction_history::TransactionHistory::new(vec![tx1, tx2, tx3, tx4]);

        let v = rule.check_transaction(&tx, &history, &cfg);
        // Only 2 consecutive 401s before the 200, so no loop
        assert!(v.is_none());
    }

    #[test]
    fn test_non_401_ignored() {
        let rule = StatefulAuthenticationFailureLoop;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        let history = crate::transaction_history::TransactionHistory::new(vec![tx1, tx2, tx3]);

        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_authentication_failure_loop");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }
}
