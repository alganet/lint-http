// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;

    /// Validate the rule's configuration. Called once at startup.
    /// Returns an error if the configuration is invalid.
    fn validate_config(&self, _config: &crate::config::Config) -> anyhow::Result<()> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _status: u16,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        None
    }
}

/// Validate all enabled rules' configurations
pub fn validate_rules(config: &crate::config::Config) -> anyhow::Result<()> {
    for rule in RULES {
        if config.is_enabled(rule.id()) {
            rule.validate_config(config).map_err(|e| {
                anyhow::anyhow!("Invalid configuration for rule '{}': {}", rule.id(), e)
            })?;
        }
    }
    Ok(())
}

pub mod client_accept_encoding_present;
pub mod client_cache_respect;
pub mod client_user_agent_present;
pub mod config_cache;
pub mod connection_efficiency;
pub mod server_cache_control_present;
pub mod server_charset_specification;
pub mod server_clear_site_data;
pub mod server_etag_or_last_modified;
pub mod server_response_405_allow;
pub mod server_x_content_type_options;

pub const RULES: &[&dyn Rule] = &[
    &server_cache_control_present::ServerCacheControlPresent,
    &server_etag_or_last_modified::ServerEtagOrLastModified,
    &server_x_content_type_options::ServerXContentTypeOptions,
    &server_response_405_allow::ServerResponse405Allow,
    &server_clear_site_data::ServerClearSiteData,
    &client_user_agent_present::ClientUserAgentPresent,
    &client_accept_encoding_present::ClientAcceptEncodingPresent,
    &client_cache_respect::ClientCacheRespect,
    &connection_efficiency::ConnectionEfficiency,
    &server_charset_specification::ServerCharsetSpecification,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{enable_rule, enable_rule_with_paths};

    #[test]
    fn rule_ids_unique_and_non_empty() {
        let mut ids = std::collections::HashSet::new();
        for rule in RULES {
            let id = rule.id();
            assert!(!id.is_empty(), "Rule id should not be empty");
            assert!(ids.insert(id), "Duplicate rule id found: {}", id);
        }
    }

    #[test]
    fn validate_rules_ok_when_enabled_rule_has_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // server_cache_control_present doesn't require config; enabling should pass
        enable_rule(&mut cfg, "server_cache_control_present");
        // server_clear_site_data requires paths; enable with valid paths too
        enable_rule_with_paths(&mut cfg, "server_clear_site_data", &["/logout"]);
        assert!(validate_rules(&cfg).is_ok());
        Ok(())
    }

    #[test]
    fn validate_rules_errors_on_invalid_rule_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // Enable server_clear_site_data but with invalid empty paths
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("paths".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("server_clear_site_data"));
        Ok(())
    }
}
