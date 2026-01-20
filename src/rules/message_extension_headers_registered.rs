// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct ExtensionHeadersConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ExtensionHeadersConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable header field-names. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed header field-names (e.g., ['host','content-type','x-custom'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['host','content-type'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(ExtensionHeadersConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageExtensionHeadersRegistered;

impl Rule for MessageExtensionHeadersRegistered {
    type Config = ExtensionHeadersConfig;

    fn id(&self) -> &'static str {
        "message_extension_headers_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_allowed_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to check headers map against allowed set
        let check_map = |headers: &hyper::HeaderMap| -> Option<Violation> {
            for (name, _val) in headers.iter() {
                let nm = name.as_str().to_ascii_lowercase();
                if !config.allowed.contains(&nm) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Header field-name '{}' is not in allowed list for '{}'. Consider adding it to the rule's 'allowed' list or registering it with IANA",
                            name.as_str(),
                            self.id()
                        ),
                    });
                }
            }
            None
        };

        // Check request headers
        if let Some(v) = check_map(&tx.request.headers) {
            return Some(v);
        }

        // Check response headers
        if let Some(resp) = &tx.response {
            if let Some(v) = check_map(&resp.headers) {
                return Some(v);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg_with_allowed(allowed: Vec<&str>) -> ExtensionHeadersConfig {
        ExtensionHeadersConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: allowed
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    #[rstest]
    #[case(vec![("host", "example")], false)]
    #[case(vec![("x-custom", "v")], false)]
    #[case(vec![("x-other", "v")], true)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host", "x-custom"]);

        // If header name cannot be parsed into HeaderName, treat as violation by test harness
        for (k, _) in &header_pairs {
            if hyper::header::HeaderName::from_bytes(k.as_bytes()).is_err() {
                assert!(
                    expect_violation,
                    "header '{}' invalid but test expected no violation",
                    k
                );
                return Ok(());
            }
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&header_pairs);

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("content-type", "text/plain")], false)]
    #[case(vec![("x-evil", "v")], true)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        // make sure default request header 'user-agent' is permitted in this config
        let cfg = make_cfg_with_allowed(vec!["content-type", "server", "user-agent"]);

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, header_pairs.as_slice());

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::config::Config::default();
        let res = parse_allowed_config(&cfg, "message_extension_headers_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_extension_headers_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_extension_headers_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("host".into()));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_extension_headers_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::String("not a table".into()),
        );

        let res = parse_allowed_config(&cfg, "message_extension_headers_registered");
        assert!(res.is_err());
    }

    #[test]
    fn unrecognized_header_reports_violation_with_name() -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        // allow default request 'user-agent' so response header is the one that triggers the violation
        let cfg = make_cfg_with_allowed(vec!["host", "user-agent"]);

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("x-unknown", "v")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_extension_headers_registered");
        assert!(v.message.contains("x-unknown"));
        Ok(())
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        full_cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("host".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<ExtensionHeadersConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"host".to_string()));
        Ok(())
    }

    #[test]
    fn header_name_matching_is_case_insensitive() -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["x-custom"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("X-CUSTOM", "1")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_unrecognized_headers_reports_first() -> anyhow::Result<()> {
        let rule = MessageExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-a", "1"), ("x-b", "2")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("x-a"));
        Ok(())
    }

    #[test]
    fn parse_config_lowercases_allowed_items() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_extension_headers_registered",
        ]);
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("X-Custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_extension_headers_registered")?;
        assert!(parsed.allowed.contains(&"x-custom".to_string()));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageExtensionHeadersRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_extension_headers_registered");
        // Provide minimal allowed array so validation succeeds
        cfg.rules.insert(
            "message_extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("host".into())]),
                );
                t
            }),
        );
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
