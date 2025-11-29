// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP response lint rules and violation reporting.

use crate::config::Config;
use hyper::HeaderMap;
use serde::Serialize;



#[derive(Clone, Serialize)]
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
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_response(client, resource, status, headers, state) {
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
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_request(client, resource, method, headers, state) {
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
    use std::net::{IpAddr, Ipv4Addr};

    fn make_test_client() -> crate::state::ClientIdentifier {
        crate::state::ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent".to_string(),
        )
    }

    #[test]
    fn lint_response_rules_emit_by_default() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        let headers = HeaderMap::new();
        let cfg = Config::default();
        let v = lint_response(&client, "http://test.com", 200, &headers, &cfg, &state);
        // Should at least recommend Cache-Control and ETag/Last-Modified
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_request_rules_emit_by_default() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        let headers = HeaderMap::new();
        let cfg = Config::default();
        let method = hyper::Method::GET;
        let v = lint_request(&client, "http://test.com", &method, &headers, &cfg, &state);
        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let client = make_test_client();
        let state = crate::state::StateStore::new(300);
        let mut rules = std::collections::HashMap::new();
        rules.insert("server_cache_control_present".to_string(), false);
        rules.insert("server_etag_or_last_modified".to_string(), false);
        let cfg = Config {
            rules,
            state: crate::config::StateConfig::default(),
        };
        let headers = HeaderMap::new();
        let v = lint_response(&client, "http://test.com", 200, &headers, &cfg, &state);
        assert!(!v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(!v.iter().any(|x| x.rule == "server_etag_or-last-modified"));
    }
}
