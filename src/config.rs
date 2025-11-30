// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Configuration loading and rule management.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct StateConfig {
    /// TTL for state entries in seconds (default: 300 = 5 minutes)
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,

    /// Whether to enable stateful analysis (default: true)
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_ttl() -> u64 {
    300
}

fn default_enabled() -> bool {
    true
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_ttl(),
            enabled: default_enabled(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
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
    #[serde(default)]
    pub rules: HashMap<String, bool>,

    #[serde(default)]
    pub state: StateConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

impl Config {
    // keep other methods on Config

    /// Load configuration from a TOML file.
    /// TOML format:
    /// \[rules\]
    /// rule-name = true
    pub async fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let s = tokio::fs::read_to_string(path_ref).await?;
        let cfg: Self = toml::from_str(&s)?;
        Ok(cfg)
    }

    pub fn is_enabled(&self, rule: &str) -> bool {
        self.rules.get(rule).copied().unwrap_or(true)
    }
}

// Default impl derived

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use uuid::Uuid;

    #[test]
    fn default_is_enabled_true() {
        let cfg = Config::default();
        assert!(cfg.is_enabled("some-rule"));
    }

    #[tokio::test]
    async fn load_toml_file() {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
server_cache_control_present = true
"#;
        fs::write(&tmp_toml, toml).await.expect("write toml");
        let cfg = Config::load_from_path(&tmp_toml).await.expect("load toml");
        assert!(cfg.is_enabled("server_cache_control_present"));
        let _ = fs::remove_file(&tmp_toml).await;
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
