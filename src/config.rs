// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Configuration loading and rule management.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct GeneralConfig {
    /// Listen address, e.g. 127.0.0.1:3000
    pub listen: String,

    /// Path to append captures JSONL
    pub captures: String,

    /// TTL for state entries in seconds (default: 300 = 5 minutes)
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,

    /// Whether to seed StateStore from captures file on startup
    #[serde(default = "default_captures_seed")]
    pub captures_seed: bool,
}

fn default_ttl() -> u64 {
    300
}

fn default_listen() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_captures() -> String {
    "captures.jsonl".to_string()
}

fn default_captures_seed() -> bool {
    false
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            captures: default_captures(),
            ttl_seconds: default_ttl(),
            captures_seed: default_captures_seed(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ca_cert_path: Option<String>,
    pub ca_key_path: Option<String>,
    #[serde(default)]
    pub passthrough_domains: Vec<String>,
    #[serde(default)]
    pub suppress_headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    pub general: GeneralConfig,

    #[serde(default)]
    pub rules: HashMap<String, toml::Value>,

    pub tls: TlsConfig,
}

impl Config {
    // keep other methods on Config

    /// Load configuration from a TOML file and return the config along with the rule engine.
    /// TOML format:
    /// `[rules]`
    /// `[[rules.<rule>]]` or `[rules.<rule>]` table with `enabled = true` and additional configuration, e.g.:
    ///
    /// [rules.server_cache_control_present]
    /// enabled = true
    ///
    /// [rules.server_clear_site_data]
    /// enabled = true
    /// paths = ["/logout", "/signout"]
    pub async fn load_from_path<P: AsRef<std::path::Path>>(
        path: P,
    ) -> anyhow::Result<(Self, crate::rules::RuleConfigEngine)> {
        let path_ref = path.as_ref();
        let s = tokio::fs::read_to_string(path_ref).await?;
        let cfg: Self = toml::from_str(&s)?;

        // Validate all enabled rules' configurations and get the engine
        let engine = crate::rules::validate_rules(&cfg)?;

        Ok((cfg, engine))
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
}

// Default impl derived

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
    async fn load_toml_file() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
    [rules.server_cache_control_present]
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
        let (cfg, _engine) = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("server_cache_control_present"));
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

    [general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false
"#;
        fs::write(&tmp_toml, toml).await?;
        let (cfg, _engine) = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.is_enabled("some_rule"));
        let config = cfg.get_rule_config("some_rule");
        assert!(config.is_some());
        fs::remove_file(&tmp_toml).await?;
        Ok(())
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
    use rstest::rstest;
    use tokio::fs;
    use uuid::Uuid;

    #[tokio::test]
    async fn load_missing_file_errors() {
        let p = std::env::temp_dir().join("lint-http_cfg_missing_does_not_exist.toml");
        let res = Config::load_from_path(&p).await;
        assert!(res.is_err());
    }

    #[rstest]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.server_clear_site_data]
enabled = true
severity = "warn"
paths = []  # Invalid: empty array
"#,
        "server_clear_site_data",
        "cannot be empty"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.server_clear_site_data]
enabled = true
severity = "warn"
paths = ["/logout", 42, "/signout"]  # Invalid: contains non-string
"#,
        "server_clear_site_data",
        "not a string"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.server_clear_site_data]
enabled = true
severity = "warn"
# Missing "paths" field entirely
other_field = "value"
"#,
        "server_clear_site_data",
        "'paths' field"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = true
# Missing severity key
"#,
        "some_rule",
        "Missing required 'severity'"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = true
severity = "critical"
"#,
        "some_rule",
        "must be one of"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
severity = "warn"
"#,
        "some_rule",
        "Missing required 'enabled'"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = "true"
severity = "warn"
"#,
        "some_rule",
        "Invalid 'enabled' for rule"
    )]
    #[tokio::test]
    async fn load_invalid_rule_config_cases(
        #[case] toml: &str,
        #[case] rule: &str,
        #[case] expected_substring: &str,
    ) -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_invalid_{}.toml", Uuid::new_v4()));
        fs::write(&tmp_toml, toml).await?;
        let res = Config::load_from_path(&tmp_toml).await;

        // Should error during validation
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains(rule));
        assert!(err_msg.contains(expected_substring));

        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }
}
