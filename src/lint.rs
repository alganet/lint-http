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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

/// Lint an entire `HttpTransaction`.
pub fn lint_transaction(
    tx: &crate::http_transaction::HttpTransaction,
    cfg: &Config,
    state: &crate::state::StateStore,
    engine: &crate::rules::RuleConfigEngine,
) -> Vec<Violation> {
    let mut out = Vec::new();

    // Compute previous transaction (if any) for this client+resource and keep it alive
    let previous = state.get_previous(&tx.client, &tx.request.uri);

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            out.extend(rule.check_transaction_erased(tx, previous.as_ref(), cfg, engine));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_helpers::{
        disable_rule, make_test_config_with_enabled_rules, make_test_engine,
    };

    #[test]
    fn lint_response_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300);
        let cfg = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let engine = make_test_engine(&cfg);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg, &state, &engine);

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
        let engine = make_test_engine(&cfg);
        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };

        let v = lint_transaction(&tx, &cfg, &state, &engine);

        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let state = crate::state::StateStore::new(300);
        let cfg_enabled = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let engine_enabled = make_test_engine(&cfg_enabled);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg_enabled, &state, &engine_enabled);
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));

        let mut cfg_disabled = Config::default();
        disable_rule(&mut cfg_disabled, "server_cache_control_present");
        disable_rule(&mut cfg_disabled, "server_etag_or_last_modified");
        let engine_disabled = make_test_engine(&cfg_disabled);
        let v2 = lint_transaction(&tx, &cfg_disabled, &state, &engine_disabled);
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
        let engine = make_test_engine(&cfg);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
        });

        let violations = lint_transaction(&tx, &cfg, &state, &engine);

        assert!(!violations.is_empty());

        let client_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "client_user_agent_present")
            .collect();
        let server_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "server_cache_control_present")
            .collect();

        assert!(!client_violations.is_empty() || !server_violations.is_empty());
    }
}
