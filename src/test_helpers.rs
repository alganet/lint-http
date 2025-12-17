// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Shared test utilities to reduce duplication across test modules.

use crate::state::{ClientIdentifier, StateStore};
use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use std::net::{IpAddr, Ipv4Addr};

/// Create a test client identifier with standard test values
#[cfg(test)]
pub fn make_test_client() -> ClientIdentifier {
    ClientIdentifier::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test-agent".to_string(),
    )
}

/// Create a test client and state store for rule testing
#[cfg(test)]
pub fn make_test_context() -> (ClientIdentifier, StateStore) {
    (make_test_client(), StateStore::new(300))
}

/// Create a HeaderMap from a slice of (key, value) pairs for use in tests
#[cfg(test)]
pub fn make_headers_from_pairs(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut hm = HeaderMap::new();
    for (k, v) in pairs {
        let name = k.parse::<HeaderName>().expect("invalid header name");
        let value = v.parse::<HeaderValue>().expect("invalid header value");
        hm.insert(name, value);
    }
    hm
}

/// Enable a rule via `[rules.<rule>]` table with `enabled = true`.
#[cfg(test)]
pub fn enable_rule(cfg: &mut crate::config::Config, rule: &str) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    // Tests that enable rules by helper should insert a default severity to
    // reduce churn (tests not concerned with severity specifics).
    table.insert(
        "severity".to_string(),
        toml::Value::String("warn".to_string()),
    );
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Enable a rule with a `paths` array under the rule table and `enabled = true`.
#[cfg(test)]
pub fn enable_rule_with_paths(cfg: &mut crate::config::Config, rule: &str, paths: &[&str]) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    // Default severity for test helpers
    table.insert(
        "severity".to_string(),
        toml::Value::String("warn".to_string()),
    );
    let arr = paths
        .iter()
        .map(|p| toml::Value::String(p.to_string()))
        .collect::<Vec<_>>();
    table.insert("paths".to_string(), toml::Value::Array(arr));
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Disable a rule via `[rules.<rule>]` table with `enabled = false`.
#[cfg(test)]
pub fn disable_rule(cfg: &mut crate::config::Config, rule: &str) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(false));
    // Include a severity key even when disabling to match new mandatory config requirement
    table.insert(
        "severity".to_string(),
        toml::Value::String("warn".to_string()),
    );
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Create a test config and enable a list of rules (table with `enabled = true`)
#[cfg(test)]
pub fn make_test_config_with_enabled_rules(rules: &[&str]) -> crate::config::Config {
    let mut cfg = crate::config::Config::default();
    for r in rules {
        enable_rule(&mut cfg, r);
    }
    cfg
}

/// Create a test config and enable rules with corresponding `paths` entries.
/// `entries` is an array of tuples: (rule_name, &[paths])
#[cfg(test)]
pub fn make_test_config_with_enabled_paths_rules(
    entries: &[(&str, &[&str])],
) -> crate::config::Config {
    let mut cfg = crate::config::Config::default();
    for (r, p) in entries {
        enable_rule_with_paths(&mut cfg, r, p);
    }
    cfg
}
/// Create a test config enabling `server_x_content_type_options` for given content types.
///
/// # Arguments
///
/// * `content_types` - Slice of content type strings to enable for the rule.
///
/// # Returns
///
/// A `Config` with the `server_x_content_type_options` rule enabled and its `content_types` set.
#[cfg(test)]
pub fn make_test_config_with_content_types(content_types: &[&str]) -> crate::config::Config {
    let mut cfg = crate::config::Config::default();
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    // Default severity for test helpers
    table.insert(
        "severity".to_string(),
        toml::Value::String("warn".to_string()),
    );
    let arr = content_types
        .iter()
        .map(|p| toml::Value::String(p.to_string()))
        .collect::<Vec<_>>();
    table.insert("content_types".to_string(), toml::Value::Array(arr));
    cfg.rules.insert(
        "server_x_content_type_options".to_string(),
        toml::Value::Table(table),
    );
    cfg
}

/// Create a minimal `HttpTransaction` for tests.
#[cfg(test)]
pub fn make_test_transaction() -> crate::http_transaction::HttpTransaction {
    use crate::http_transaction::{HttpTransaction, TimingInfo};

    let mut tx = HttpTransaction::new(
        make_test_client(),
        "GET".to_string(),
        "http://example/".to_string(),
    );
    let mut hm = HeaderMap::new();
    hm.insert("user-agent", HeaderValue::from_static("test-agent"));
    tx.request.headers = hm;
    tx.timing = TimingInfo { duration_ms: 5 };
    tx
}

/// Create a `HttpTransaction` with a response and provided headers for tests.
#[cfg(test)]
pub fn make_test_transaction_with_response(
    status: u16,
    resp_headers: &[(&str, &str)],
) -> crate::http_transaction::HttpTransaction {
    use crate::http_transaction::ResponseInfo;

    let mut tx = make_test_transaction();
    let headers = make_headers_from_pairs(resp_headers);
    tx.response = Some(ResponseInfo { status, headers });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_test_transaction_basic() {
        let tx = make_test_transaction();
        assert_eq!(tx.request.method, "GET");
        assert_eq!(tx.request.uri, "http://example/");
        assert_eq!(
            tx.request
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok()),
            Some("test-agent")
        );
    }

    #[test]
    fn test_make_test_transaction_with_response_basic() {
        let tx = make_test_transaction_with_response(200, &[("etag", "\"abc\"")]);
        assert!(tx.response.is_some());
        assert_eq!(tx.response.unwrap().status, 200);
    }
}
