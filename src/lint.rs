// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP request/response linting and rule evaluation.

use crate::config::Config;
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};

/// Represents a single rule violation detected by the linter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Violation {
    pub rule: String,
    pub severity: String,
    pub message: String,
}

pub fn lint_response(
    client: &crate::state::ClientIdentifier,
    resource: &str,
    status: u16,
    headers: &HeaderMap,
    conn: &crate::connection::ConnectionMetadata,
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) =
                rule.check_response(client, resource, status, headers, conn, state, cfg)
            {
                out.push(v);
            }
        }
    }

    out
}

pub fn lint_request(
    client: &crate::state::ClientIdentifier,
    resource: &str,
    method: &hyper::Method,
    headers: &HeaderMap,
    conn: &crate::connection::ConnectionMetadata,
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_request(client, resource, method, headers, conn, state, cfg)
            {
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
    use crate::test_helpers::{
        disable_rule, make_test_client, make_test_config_with_enabled_rules, make_test_conn,
    };

    #[test]
    fn lint_response_rules_emit_when_enabled() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        let headers = HeaderMap::new();
        let cfg = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let conn = make_test_conn();
        let v = lint_response(
            &client,
            "http://test.com",
            200,
            &headers,
            &conn,
            &cfg,
            &state,
        );
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_request_rules_emit_when_enabled() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        let headers = HeaderMap::new();
        let cfg = make_test_config_with_enabled_rules(&[
            "client_user_agent_present",
            "client_accept_encoding_present",
        ]);
        let method = hyper::Method::GET;
        let conn = make_test_conn();
        let v = lint_request(
            &client,
            "http://test.com",
            &method,
            &headers,
            &conn,
            &cfg,
            &state,
        );
        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        // Enable rules explicitly, then disable them to ensure toggle behavior works
        let cfg_enabled = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let v = lint_response(
            &client,
            "http://test.com",
            200,
            &headers,
            &conn,
            &cfg_enabled,
            &state,
        );
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
        // If we disable these rules (or don't enable them), they should not produce violations
        let mut cfg_disabled = Config::default();
        disable_rule(&mut cfg_disabled, "server_cache_control_present");
        disable_rule(&mut cfg_disabled, "server_etag_or_last_modified");
        let v2 = lint_response(
            &client,
            "http://test.com",
            200,
            &headers,
            &conn,
            &cfg_disabled,
            &state,
        );
        assert!(!v2.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(!v2.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }
}
