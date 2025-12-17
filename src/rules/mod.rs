// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::state::StateStore;

/// The `Rule` trait defines a single hook that runs on the canonical
/// `HttpTransaction`. All rules must implement `check_transaction`.
/// Scope of a rule: whether it applies to client-only traffic (requests),
/// server-only traffic (responses), or both (full transactions).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuleScope {
    Client,
    Server,
    Both,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;

    /// Validate the rule's configuration. Called once at startup.
    /// Returns an error if the configuration is invalid.
    fn validate_config(&self, _config: &crate::config::Config) -> anyhow::Result<()> {
        Ok(())
    }

    /// The scope where the rule should be executed. Default is `Both` for
    /// backward compatibility; rules may override for better precision.
    fn scope(&self) -> RuleScope {
        RuleScope::Both
    }

    /// Evaluate an entire `HttpTransaction` and return an optional violation.
    fn check_transaction(
        &self,
        _tx: &crate::http_transaction::HttpTransaction,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation>;
}

/// Lookup the configured severity for a rule at runtime,
/// This function assumes that configuration validation has already ensured the presence and validity
/// of the `severity` key, but panics with a clear message if something is wrong
/// at runtime (defensive assertion).
pub fn get_rule_severity(cfg: &crate::config::Config, rule: &str) -> crate::lint::Severity {
    // If rule config is missing (e.g. tests using Config::default()), fall back
    // to a sensible default to avoid panics during unit tests. Runtime config
    // validation (load_from_path) ensures that TOML files include a severity.
    let Some(rule_cfg) = cfg.get_rule_config(rule) else {
        return crate::lint::Severity::Warn;
    };
    let Some(table) = rule_cfg.as_table() else {
        return crate::lint::Severity::Warn;
    };
    let Some(s) = table.get("severity").and_then(|v| v.as_str()) else {
        return crate::lint::Severity::Warn;
    };
    match s {
        "info" => crate::lint::Severity::Info,
        "warn" => crate::lint::Severity::Warn,
        "error" => crate::lint::Severity::Error,
        _ => crate::lint::Severity::Warn,
    }
}

pub fn validate_rules(config: &crate::config::Config) -> anyhow::Result<()> {
    // Ensure every rule table specifies a valid `severity` entry.
    for (rule_name, val) in &config.rules {
        if let toml::Value::Table(table) = val {
            match table.get("severity") {
                Some(toml::Value::String(s)) => match s.as_str() {
                    "info" | "warn" | "error" => {}
                    _ => {
                        return Err(anyhow::anyhow!(
                                "Invalid severity '{}' for rule '{}': must be one of 'info', 'warn', 'error'",
                                s,
                                rule_name
                            ));
                    }
                },
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "Invalid severity for rule '{}': must be a string 'info', 'warn', or 'error'",
                        rule_name
                    ));
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing required 'severity' key for rule '{}'",
                        rule_name
                    ));
                }
            }
        }
    }

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
pub mod client_host_header;
pub mod client_request_method_token_uppercase;
pub mod client_user_agent_present;
pub mod message_connection_header_tokens_valid;
pub mod message_connection_upgrade;
pub mod message_content_length;
pub mod message_content_length_vs_transfer_encoding;
pub mod message_header_field_names_token;
pub mod message_transfer_encoding_chunked_final;
pub mod server_cache_control_present;
pub mod server_charset_specification;
pub mod server_clear_site_data;
pub mod server_content_type_present;
pub mod server_etag_or_last_modified;
pub mod server_no_body_for_1xx_204_304;
pub mod server_response_405_allow;
pub mod server_x_content_type_options;

pub const RULES: &[&dyn Rule] = &[
    &server_cache_control_present::ServerCacheControlPresent,
    &server_etag_or_last_modified::ServerEtagOrLastModified,
    &server_x_content_type_options::ServerXContentTypeOptions,
    &server_response_405_allow::ServerResponse405Allow,
    &server_clear_site_data::ServerClearSiteData,
    &server_no_body_for_1xx_204_304::ServerNoBodyFor1xx204304,
    &client_user_agent_present::ClientUserAgentPresent,
    &client_accept_encoding_present::ClientAcceptEncodingPresent,
    &client_cache_respect::ClientCacheRespect,
    &client_host_header::ClientHostHeader,
    &client_request_method_token_uppercase::ClientRequestMethodTokenUppercase,
    &message_content_length_vs_transfer_encoding::MessageContentLengthVsTransferEncoding,
    &message_content_length::MessageContentLength,
    &message_header_field_names_token::MessageHeaderFieldNamesToken,
    &message_transfer_encoding_chunked_final::MessageTransferEncodingChunkedFinal,
    &message_connection_header_tokens_valid::MessageConnectionHeaderTokensValid,
    &server_content_type_present::ServerContentTypePresent,
    &message_connection_upgrade::MessageConnectionUpgrade,
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
    fn config_example_includes_all_rules() -> anyhow::Result<()> {
        let s = std::fs::read_to_string("config_example.toml")?;

        for rule in RULES {
            let id = rule.id();
            let marker = format!("[rules.{}]", id);
            assert!(
                s.contains(&marker),
                "config_example.toml missing example for rule '{}'",
                id
            );
        }

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
