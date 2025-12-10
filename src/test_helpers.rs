// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Shared test utilities to reduce duplication across test modules.

use crate::state::{ClientIdentifier, StateStore};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Create a test client identifier with standard test values
pub fn make_test_client() -> ClientIdentifier {
    ClientIdentifier::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test-agent".to_string(),
    )
}

/// Create a test client and state store for rule testing
pub fn make_test_context() -> (ClientIdentifier, StateStore) {
    (make_test_client(), StateStore::new(300))
}

/// Create a test config with default values
pub fn make_test_config() -> crate::config::Config {
    crate::config::Config::default()
}

/// Create a test connection metadata with standard test address
pub fn make_test_conn() -> crate::connection::ConnectionMetadata {
    crate::connection::ConnectionMetadata::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        12345,
    ))
}

/// Enable a rule via `[rules.<rule>]` table with `enabled = true`.
pub fn enable_rule(cfg: &mut crate::config::Config, rule: &str) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Enable a rule with a `paths` array under the rule table and `enabled = true`.
pub fn enable_rule_with_paths(cfg: &mut crate::config::Config, rule: &str, paths: &[&str]) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    let arr = paths
        .iter()
        .map(|p| toml::Value::String(p.to_string()))
        .collect::<Vec<_>>();
    table.insert("paths".to_string(), toml::Value::Array(arr));
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Disable a rule via `[rules.<rule>]` table with `enabled = false`.
pub fn disable_rule(cfg: &mut crate::config::Config, rule: &str) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(false));
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

/// Create a test config and enable a list of rules (table with `enabled = true`)
pub fn make_test_config_with_enabled_rules(rules: &[&str]) -> crate::config::Config {
    let mut cfg = make_test_config();
    for r in rules {
        enable_rule(&mut cfg, r);
    }
    cfg
}

/// Create a test config and enable rules with corresponding `paths` entries.
/// `entries` is an array of tuples: (rule_name, &[paths])
pub fn make_test_config_with_enabled_paths_rules(
    entries: &[(&str, &[&str])],
) -> crate::config::Config {
    let mut cfg = make_test_config();
    for (r, p) in entries {
        enable_rule_with_paths(&mut cfg, r, p);
    }
    cfg
}
