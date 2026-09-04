// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Rule configuration loading and lookup.
//!
//! This module holds only the lint-facing configuration surface: the
//! `[rules.*]` and `[violations.*]` tables. Transport configuration (listen
//! addresses, TLS,
//! captures, HTTP/3 upstream policy) belongs to the proxy binary and lives in
//! `lint-http-proxy`, which flattens this struct into its own `Config` — so
//! the rule layer depends only on what it actually reads, and this crate can
//! be reused outside the proxy (HAR/PCAP analyzers, CI fixture linting,
//! replay harnesses) without inventing a listen address.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub rules: HashMap<String, toml::Value>,
    /// The `[violations.*]` tables: per-defect overrides, keyed by violation
    /// id. Absent by default and expected to stay mostly absent — a
    /// violation's severity has a default on its catalogue entry, so a table
    /// here is what an operator writes when they disagree with it.
    ///
    /// A second table rather than keys inside `[rules.<id>]`, because a defect
    /// is not owned by the rule that reports it: two rules may report the same
    /// one, and merging two rules must not rename what either of them says.
    /// Kept as `toml::Value` for the same reason `rules` is — this crate sits
    /// below the catalogue and cannot know which ids exist.
    /// `rules::validate_rules` checks them against it.
    #[serde(default)]
    pub violations: HashMap<String, toml::Value>,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// This performs only structural parsing; sections other than `[rules]`
    /// (e.g. a proxy config's `[general]`/`[tls]`) are ignored, so a full
    /// proxy config file parses here too. Per-rule config validation lives in
    /// the rule layer (`rules::validate_rules`) and is invoked by the caller
    /// after load — this keeps `config` free of any dependency on the rule
    /// catalogue, so it can sit in a lower crate than the rules.
    pub async fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let s = tokio::fs::read_to_string(path.as_ref()).await?;
        Ok(toml::from_str(&s)?)
    }

    /// Returns true if the rule is enabled.
    ///
    /// Rules are disabled by default. A rule is enabled only when there is a
    /// TOML table under `[rules.<rule>]` that contains `enabled = true`.
    pub fn is_enabled(&self, rule: &str) -> bool {
        match self.rules.get(rule) {
            Some(toml::Value::Table(table)) => {
                matches!(table.get("enabled"), Some(toml::Value::Boolean(true)))
            }
            _ => false,
        }
    }

    /// Gets the configuration value for a rule.
    pub fn get_rule_config(&self, rule: &str) -> Option<&toml::Value> {
        self.rules.get(rule)
    }

    /// The `[violations.<id>]` table, when the configuration wrote one.
    ///
    /// There is no `is_enabled` twin: a defect cannot be switched off on its
    /// own, because most rules return their first finding and stop, so
    /// silencing one defect would silence whatever the same branch would have
    /// reported after it. Severity is the whole of what this table decides.
    pub fn get_violation_config(&self, violation: &str) -> Option<&toml::Value> {
        self.violations.get(violation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{disable_rule, enable_rule_with_paths};
    use tokio::fs;
    use uuid::Uuid;

    #[test]
    fn default_is_enabled_false() {
        let cfg = Config::default();
        assert!(!cfg.is_enabled("some-rule"));
    }

    #[tokio::test]
    async fn load_toml_file_ignoring_transport_sections() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
    [rules.cache_control_present]
    enabled = true
    severity = "warn"

    [general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300
captures_seed = false

[tls]
enabled = false
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("cache_control_present"));
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_rules_only_file() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
    [rules.cache_control_present]
    enabled = true
    severity = "warn"
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("cache_control_present"));
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_rule_with_config_value() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
    [rules.some_rule]
    enabled = true
    severity = "warn"
    paths = ["/logout", "/signout"]
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("some_rule"));
        let config = cfg.get_rule_config("some_rule");
        assert!(config.is_some());
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    /// The second table loads beside the first, and neither knows about the
    /// other: a file may carry `[violations]` alone, `[rules]` alone, or both.
    #[tokio::test]
    async fn load_violation_severity_override() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules.cache_control_present]
enabled = true
severity = "warn"

[violations.cache_control_absent]
severity = "error"
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("cache_control_present"));
        let table = cfg
            .get_violation_config("cache_control_absent")
            .and_then(toml::Value::as_table)
            .expect("the override is a table");
        assert_eq!(
            table.get("severity").and_then(toml::Value::as_str),
            Some("error")
        );
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    /// Nothing is configured by default, which is what makes the table an
    /// override: a file that writes none reports every defect at the severity
    /// its catalogue entry carries.
    #[test]
    fn no_violation_is_configured_by_default() {
        let cfg = Config::default();
        assert!(cfg.violations.is_empty());
        assert!(cfg.get_violation_config("some_violation").is_none());
    }

    #[test]
    fn rule_disabled_with_false() {
        let mut cfg = Config::default();
        disable_rule(&mut cfg, "test_rule");
        assert!(!cfg.is_enabled("test_rule"));
    }

    #[test]
    fn rule_disabled_with_table_enabled_false() {
        let mut cfg = Config::default();
        disable_rule(&mut cfg, "test_rule_table");
        assert!(!cfg.is_enabled("test_rule_table"));
    }

    #[test]
    fn rule_enabled_with_config_value() {
        let mut cfg = Config::default();
        enable_rule_with_paths(&mut cfg, "test_rule", &["/logout"]);
        assert!(cfg.is_enabled("test_rule"));
    }
    #[test]
    fn get_rule_config_none_returns_none() {
        let cfg = Config::default();
        assert!(cfg.get_rule_config("nonexistent").is_none());
    }
    #[test]
    fn table_without_enabled_is_disabled() {
        let mut cfg = Config::default();
        let mut table = toml::map::Map::new();
        table.insert(
            "paths".to_string(),
            toml::Value::Array(vec![toml::Value::String("/logout".to_string())]),
        );
        cfg.rules.insert(
            "test_rule_table_no_enabled".to_string(),
            toml::Value::Table(table),
        );
        assert!(!cfg.is_enabled("test_rule_table_no_enabled"));
    }

    #[test]
    fn boolean_true_does_not_enable_rule() {
        let mut cfg = Config::default();
        cfg.rules
            .insert("some_rule_bool".to_string(), toml::Value::Boolean(true));
        assert!(!cfg.is_enabled("some_rule_bool"));
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[tokio::test]
    async fn load_missing_file_errors() {
        let p = std::env::temp_dir().join("lint-http_cfg_missing_does_not_exist.toml");
        let res = Config::load_from_path(&p).await;
        assert!(res.is_err());
    }
}
