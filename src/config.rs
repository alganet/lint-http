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
    pub rules: HashMap<String, bool>,

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

[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300
captures_seed = false

[tls]
enabled = false
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
