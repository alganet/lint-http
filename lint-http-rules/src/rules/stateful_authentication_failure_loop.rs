// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Detects repeated 401 challenges for the same protection space (origin),
/// which indicates an authentication failure loop.
pub struct StatefulAuthenticationFailureLoop;

impl Rule for StatefulAuthenticationFailureLoop {
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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

    fn description(&self) -> &'static str {
        "Detects repeated `401 Unauthorized` challenges for the same protection space (origin), which strongly indicates an authentication failure loop. When a client continuously retries authentication and repeatedly fails with a 401 across the same origin, it could imply a broken client, misconfigured credentials, or a flawed authentication handshake.\n\nThis rule tracks the transaction history by origin and flags if a client receives 4 or more consecutive `401 Unauthorized` challenges without a successful (or other non-401) response in between."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9110 §11.6.2 — 401 Unauthorized](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2)",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 200 OK HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Authentication Loop"),
                snippet: "> GET /api/v1/data HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulAuthenticationFailureLoop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_loop_detected() {
        let rule = StatefulAuthenticationFailureLoop;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.request.uri = "https://example.com/protected".to_string();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx1.request.uri = "https://example.com/login".to_string();

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx2.request.uri = "https://example.com/api".to_string();

        let mut tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx3.request.uri = "https://example.com/admin".to_string();

        // supply history newest-first; tx3 is most recent
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![tx3, tx2, tx1]);

        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_authentication_failure_loop",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("4 consecutive"));
    }

    #[test]
    fn test_auth_loop_broken_by_200() {
        let rule = StatefulAuthenticationFailureLoop;

        let tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        // put newest transaction first (tx4) to satisfy TransactionHistory
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            tx4, tx3, tx2, tx1,
        ]);

        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_authentication_failure_loop",
            ]),
        );
        // Only 2 consecutive 401s before the 200, so no loop
        assert!(v.is_none());
    }

    #[test]
    fn test_non_401_ignored() {
        let rule = StatefulAuthenticationFailureLoop;

        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        // newest-first history
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![tx3, tx2, tx1]);

        let v = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_authentication_failure_loop",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_authentication_failure_loop");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
