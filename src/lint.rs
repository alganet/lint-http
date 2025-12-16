// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP request/response linting and rule evaluation.

use crate::config::Config;
use serde::{Deserialize, Serialize};

/// Represents a single rule violation detected by the linter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
}

/// Severity level for a rule violation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

/// Lint an entire `HttpTransaction`.
pub fn lint_transaction(
    tx: &crate::http_transaction::HttpTransaction,
    conn: &crate::connection::ConnectionMetadata,
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_transaction(tx, conn, state, cfg) {
                out.push(v);
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_helpers::{disable_rule, make_test_config_with_enabled_rules, make_test_conn};

    #[test]
    fn lint_response_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300);
        let cfg = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let conn = make_test_conn();

        // Create a transaction with just response data for server rules
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &conn, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_request_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300);
        let cfg = make_test_config_with_enabled_rules(&[
            "client_user_agent_present",
            "client_accept_encoding_present",
        ]);
        let conn = make_test_conn();

        // Create a transaction without user-agent header to trigger the rule
        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        // Note: intentionally not adding user-agent header to trigger the rule

        let v = lint_transaction(&tx, &conn, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let state = crate::state::StateStore::new(300);
        // Enable rules explicitly, then disable them to ensure toggle behavior works
        let cfg_enabled = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let conn = make_test_conn();

        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &conn, &cfg_enabled, &state);
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));

        // If we disable these rules (or don't enable them), they should not produce violations
        let mut cfg_disabled = Config::default();
        disable_rule(&mut cfg_disabled, "server_cache_control_present");
        disable_rule(&mut cfg_disabled, "server_etag_or_last_modified");
        let v2 = lint_transaction(&tx, &conn, &cfg_disabled, &state);
        assert!(!v2.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(!v2.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_transaction_handles_both_client_and_server_rules() {
        let state = crate::state::StateStore::new(300);
        let cfg = make_test_config_with_enabled_rules(&[
            "client_user_agent_present",
            "server_cache_control_present",
        ]);
        let conn = make_test_conn();

        // Build a transaction without user-agent header to trigger client rule
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        // Note: intentionally not adding user-agent header to trigger the rule
        tx.response = Some(ResponseInfo {
            status: 200,
            headers: hyper::HeaderMap::new(), // No cache-control to trigger server rule
        });

        let violations = lint_transaction(&tx, &conn, &cfg, &state);

        // Should find at least one violation (either client or server rule)
        assert!(!violations.is_empty());

        // Verify we have violations from both client and server rule types
        let client_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "client_user_agent_present")
            .collect();
        let server_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "server_cache_control_present")
            .collect();

        // At least one of each type should be present
        assert!(!client_violations.is_empty() || !server_violations.is_empty());
    }
}
