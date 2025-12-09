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
