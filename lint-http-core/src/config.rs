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

    /// Maximum number of transactions to keep per (client, resource) key
    #[serde(default = "default_max_history")]
    pub max_history: usize,

    /// Maximum number of protocol events to keep per connection/session key.
    /// Protocol-level rules (e.g. WebSocket frame sequencing) may need a
    /// larger window than `max_history` to detect violations across many
    /// frames.  Defaults to 200.
    #[serde(default = "default_max_protocol_event_history")]
    pub max_protocol_event_history: usize,

    /// Whether to seed StateStore from captures file on startup
    #[serde(default = "default_captures_seed")]
    pub captures_seed: bool,

    /// Whether captured bodies should be included in the serialized captures file.
    /// Bodies are still captured in memory for rules; this flag controls whether
    /// bodies are written into `captures` (default: false).
    #[serde(default = "default_captures_include_body")]
    pub captures_include_body: bool,

    /// Cap on the one body still buffered fully in memory: the WebSocket upgrade
    /// handshake request, which must be replayed upstream as a single buffer
    /// (default: 64 MiB). An over-limit handshake body is rejected with 413 and
    /// marked `request_body_over_limit`, with the body not captured. Since the
    /// streaming pipeline shipped, H1/H2/H3 request/response bodies are *not*
    /// bounded by this — they stream through, and only the captured copy is
    /// bounded, by `captures_max_body_bytes`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Maximum number of body bytes captured into the transaction for rules and
    /// the captures file (default: 1 MiB). Bodies are forwarded in full
    /// regardless; only the captured copy is bounded to this prefix. When a body
    /// exceeds it, `request_body_over_limit` / `response_body_over_limit` mark
    /// the captured body as a truncated prefix (the real size is still recorded
    /// in `body_length`).
    #[serde(default = "default_captures_max_body_bytes")]
    pub captures_max_body_bytes: usize,

    /// Maximum number of simultaneous live TCP connections the proxy will
    /// serve. Further connections wait for a slot rather than being accepted
    /// unboundedly (default: 1024).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// On shutdown (Ctrl-C), how many seconds to wait for in-flight handlers
    /// to drain before exiting anyway (default: 30).
    #[serde(default = "default_shutdown_timeout_seconds")]
    pub shutdown_timeout_seconds: u64,

    /// Optional HTTP/3 (QUIC) listen address, e.g. "127.0.0.1:3443".
    /// When set, a QUIC/HTTP3 endpoint is started alongside the TCP listener.
    /// Requires TLS to be enabled.
    #[serde(default)]
    pub h3_listen: Option<String>,

    /// Server name (SNI) for the HTTP/3 TLS certificate, e.g. "proxy.example.com".
    /// Defaults to "localhost" when omitted. Clients must connect using this name.
    #[serde(default)]
    pub h3_server_name: Option<String>,

    /// Enable the HTTP/3 (QUIC) *upstream* leg: when set, requests whose origin
    /// authority is listed in `h3_upstream_authorities` are forwarded to the
    /// origin over HTTP/3 instead of the hyper H1/H2 client (default: false).
    /// Independent of `h3_listen` (that is the client-facing H3 *server*).
    #[serde(default)]
    pub h3_upstream_enabled: bool,

    /// Origin authorities (`host:port`) to forward over HTTP/3 when
    /// `h3_upstream_enabled` is set. Until Alt-Svc discovery lands, this
    /// allowlist is the only capability signal that an origin speaks H3.
    #[serde(default)]
    pub h3_upstream_authorities: Vec<String>,

    /// UDP socket address the HTTP/3 upstream client binds for its QUIC
    /// endpoint. Defaults to "0.0.0.0:0" (ephemeral) when omitted.
    #[serde(default)]
    pub h3_upstream_bind: Option<String>,

    /// Extra CA certificate PEM files to trust when validating an origin's
    /// HTTP/3 endpoint certificate, in addition to the platform trust store.
    /// For origins fronted by a private CA (and for driving an in-process H3
    /// origin under test). Empty by default.
    #[serde(default)]
    pub h3_upstream_extra_ca_certs: Vec<String>,

    /// How long (ms) to wait for the HTTP/3 upstream QUIC connect + handshake
    /// (and the response head) before treating the attempt as failed and
    /// falling back to H1/H2 (default: 5000).
    #[serde(default = "default_h3_upstream_connect_timeout_ms")]
    pub h3_upstream_connect_timeout_ms: u64,

    /// Base backoff (seconds) for the H3 upstream negative cache: after a
    /// connect/handshake failure an origin authority is not retried over H3
    /// until this window (doubling per consecutive failure) elapses, so a
    /// non-H3 origin isn't probed on every request (default: 30).
    #[serde(default = "default_h3_upstream_negative_ttl_seconds")]
    pub h3_upstream_negative_ttl_seconds: u64,

    /// Whether the live capture stream endpoint (`GET /_lint_http/stream`, an
    /// SSE feed of each transaction as it commits) is served. It exposes every
    /// proxied transaction (and body prefixes when `captures_include_body` is
    /// set) to anyone who can reach the proxy port, so it is opt-in: when
    /// disabled the endpoint returns 404 (default: false).
    #[serde(default = "default_live_stream_enabled")]
    pub live_stream_enabled: bool,
}

fn default_ttl() -> u64 {
    300
}

fn default_max_history() -> usize {
    10
}

fn default_max_protocol_event_history() -> usize {
    200
}

const fn default_captures_include_body() -> bool {
    false
}

const fn default_max_body_bytes() -> usize {
    64 * 1024 * 1024
}

const fn default_captures_max_body_bytes() -> usize {
    1024 * 1024
}

const fn default_max_connections() -> usize {
    1024
}

const fn default_shutdown_timeout_seconds() -> u64 {
    30
}

const fn default_h3_upstream_connect_timeout_ms() -> u64 {
    5000
}

const fn default_h3_upstream_negative_ttl_seconds() -> u64 {
    30
}

fn default_listen() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_captures() -> String {
    "captures.jsonl".to_string()
}

const fn default_captures_seed() -> bool {
    false
}

const fn default_live_stream_enabled() -> bool {
    false
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            captures: default_captures(),
            ttl_seconds: default_ttl(),
            max_history: default_max_history(),
            max_protocol_event_history: default_max_protocol_event_history(),
            captures_seed: default_captures_seed(),
            captures_include_body: default_captures_include_body(),
            max_body_bytes: default_max_body_bytes(),
            captures_max_body_bytes: default_captures_max_body_bytes(),
            max_connections: default_max_connections(),
            shutdown_timeout_seconds: default_shutdown_timeout_seconds(),
            h3_listen: None,
            h3_server_name: None,
            h3_upstream_enabled: false,
            h3_upstream_authorities: Vec::new(),
            h3_upstream_bind: None,
            h3_upstream_extra_ca_certs: Vec::new(),
            h3_upstream_connect_timeout_ms: default_h3_upstream_connect_timeout_ms(),
            h3_upstream_negative_ttl_seconds: default_h3_upstream_negative_ttl_seconds(),
            live_stream_enabled: default_live_stream_enabled(),
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
    /// Load configuration from a TOML file.
    ///
    /// This performs only structural parsing and config-level invariants (e.g.
    /// `h3_listen` requires TLS). Per-rule config validation lives in the rule
    /// layer (`rules::validate_rules`) and is invoked by the caller after load
    /// — this keeps `config` free of any dependency on the rule catalogue, so
    /// it can sit in a lower crate than the rules.
    pub async fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let s = tokio::fs::read_to_string(path_ref).await?;
        let cfg: Self = toml::from_str(&s)?;

        // h3_listen requires TLS to be enabled
        if cfg.general.h3_listen.is_some() && !cfg.tls.enabled {
            anyhow::bail!("h3_listen requires [tls] enabled = true");
        }

        Ok(cfg)
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
        let cfg = Config::load_from_path(&tmp_toml).await?;
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
        let cfg = Config::load_from_path(&tmp_toml).await?;
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

    #[test]
    fn h3_listen_defaults_to_none() {
        let cfg = Config::default();
        assert!(cfg.general.h3_listen.is_none());
    }

    #[test]
    fn max_body_bytes_defaults_to_64_mib() {
        let cfg = Config::default();
        assert_eq!(cfg.general.max_body_bytes, 64 * 1024 * 1024);
    }

    #[tokio::test]
    async fn max_body_bytes_parsed_when_present() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
max_body_bytes = 1024

[tls]
enabled = false
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert_eq!(cfg.general.max_body_bytes, 1024);
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    #[tokio::test]
    async fn h3_listen_parsed_when_present() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
h3_listen = "127.0.0.1:3443"

[tls]
enabled = true
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert_eq!(cfg.general.h3_listen, Some("127.0.0.1:3443".to_string()));
        fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

    #[tokio::test]
    async fn h3_listen_without_tls_fails() {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
h3_listen = "127.0.0.1:3443"

[tls]
enabled = false
"#;
        fs::write(&tmp_toml, toml).await.unwrap();
        let result = Config::load_from_path(&tmp_toml).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("h3_listen requires"),
            "unexpected error: {}",
            err_msg
        );
        let _ = fs::remove_file(&tmp_toml).await;
    }

    #[tokio::test]
    async fn h3_listen_absent_is_none() -> anyhow::Result<()> {
        let tmp_toml =
            std::env::temp_dir().join(format!("lint-http_cfg_test_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false
"#;
        fs::write(&tmp_toml, toml).await?;
        let cfg = Config::load_from_path(&tmp_toml).await?;
        assert!(cfg.general.h3_listen.is_none());
        fs::remove_file(&tmp_toml).await?;
        Ok(())
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
