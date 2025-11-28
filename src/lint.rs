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

pub fn lint_response(status: u16, headers: &HeaderMap, cfg: &Config) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_response(status, headers) {
                out.push(v);
            }
        }
    }

    out
}

pub fn lint_request(method: &hyper::Method, headers: &HeaderMap, cfg: &Config) -> Vec<Violation> {
    let mut out = Vec::new();

    for rule in crate::rules::RULES {
        if cfg.is_enabled(rule.id()) {
            if let Some(v) = rule.check_request(method, headers) {
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

    #[test]
    fn lint_response_rules_emit_by_default() {
        let headers = HeaderMap::new();
        let cfg = Config::default();
        let v = lint_response(200, &headers, &cfg);
        // Should at least recommend Cache-Control and ETag/Last-Modified
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_request_rules_emit_by_default() {
        let headers = HeaderMap::new();
        let cfg = Config::default();
        let method = hyper::Method::GET;
        let v = lint_request(&method, &headers, &cfg);
        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let mut rules = std::collections::HashMap::new();
        rules.insert("server_cache_control_present".to_string(), false);
        rules.insert("server_etag_or_last_modified".to_string(), false);
        let cfg = Config { rules };
        let headers = HeaderMap::new();
        let v = lint_response(200, &headers, &cfg);
        assert!(!v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(!v.iter().any(|x| x.rule == "server_etag_or-last-modified"));
    }
}
