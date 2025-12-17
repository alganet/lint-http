// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities.

use crate::state::ClientIdentifier;
use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(test)]
pub fn make_test_client() -> ClientIdentifier {
    ClientIdentifier::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test-agent".to_string(),
    )
}

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

#[cfg(test)]
fn insert_rule_config(
    cfg: &mut crate::config::Config,
    rule: &str,
    enabled: bool,
    paths: Option<&[&str]>,
) {
    let mut table = toml::map::Map::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(enabled));
    table.insert(
        "severity".to_string(),
        toml::Value::String("warn".to_string()),
    );
    if let Some(path_list) = paths {
        let arr = path_list
            .iter()
            .map(|p| toml::Value::String(p.to_string()))
            .collect::<Vec<_>>();
        table.insert("paths".to_string(), toml::Value::Array(arr));
    }
    cfg.rules
        .insert(rule.to_string(), toml::Value::Table(table));
}

#[cfg(test)]
pub fn enable_rule(cfg: &mut crate::config::Config, rule: &str) {
    insert_rule_config(cfg, rule, true, None);
}

#[cfg(test)]
pub fn enable_rule_with_paths(cfg: &mut crate::config::Config, rule: &str, paths: &[&str]) {
    insert_rule_config(cfg, rule, true, Some(paths));
}

#[cfg(test)]
pub fn disable_rule(cfg: &mut crate::config::Config, rule: &str) {
    insert_rule_config(cfg, rule, false, None);
}

#[cfg(test)]
pub fn make_test_config_with_enabled_rules(rules: &[&str]) -> crate::config::Config {
    let mut cfg = crate::config::Config::default();
    for r in rules {
        enable_rule(&mut cfg, r);
    }
    cfg
}

#[cfg(test)]
pub fn make_test_engine(cfg: &crate::config::Config) -> crate::rules::RuleConfigEngine {
    crate::rules::validate_rules(cfg).expect("test config should be valid")
}

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
pub fn make_test_rule_config() -> crate::rules::RuleConfig {
    crate::rules::RuleConfig {
        enabled: true,
        severity: crate::lint::Severity::Warn,
    }
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
