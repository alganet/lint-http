// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::config_cache::RuleConfigCache;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

static CACHED_PATHS: RuleConfigCache<Vec<String>> = RuleConfigCache::new();

pub struct ServerClearSiteData;

/// Parse and validate paths configuration for this rule
fn parse_paths_config(config: &crate::config::Config) -> anyhow::Result<Vec<String>> {
    // Require a configuration table for this rule. If none is provided, return an error
    // since this rule is not enabled by default and configuration is required to enable it.
    let Some(rule_config) = config.get_rule_config("server_clear_site_data") else {
        return Err(anyhow::anyhow!(
            r#"rule 'server_clear_site_data' requires configuration to be enabled. Example:
[rules.server_clear_site_data]
enabled = true
paths = ["/logout"]"#
        ));
    };

    // If config is provided, it must be a table with a "paths" array
    let table = rule_config.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Configuration must be a table with 'paths' field, e.g., [rules.server_clear_site_data]\npaths = [\"/logout\"]"
        )
    })?;

    // "paths" field is required
    let paths_value = table.get("paths").ok_or_else(|| {
        anyhow::anyhow!("Configuration table must contain 'paths' field with array of strings")
    })?;

    // "paths" must be an array
    let paths_array = paths_value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "'paths' field must be an array of strings, e.g., paths = [\"/logout\", \"/signout\"]"
        )
    })?;

    // Array must not be empty
    if paths_array.is_empty() {
        return Err(anyhow::anyhow!(
            "'paths' array cannot be empty - provide at least one path or disable the rule"
        ));
    }

    // Parse and validate all items
    let mut paths = Vec::new();
    for (idx, item) in paths_array.iter().enumerate() {
        let path = item.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "'paths' array item at index {} is not a string: {:?}",
                idx,
                item
            )
        })?;
        paths.push(path.to_string());
    }

    Ok(paths)
}

impl Rule for ServerClearSiteData {
    fn id(&self) -> &'static str {
        "server_clear_site_data"
    }

    fn validate_config(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        // Parse and cache the config - if it succeeds, config is valid
        let paths = parse_paths_config(config)?;
        CACHED_PATHS.set(paths);
        Ok(())
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        resource: &str,
        status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        config: &crate::config::Config,
    ) -> Option<Violation> {
        // Only check successful responses
        if !(200..300).contains(&status) {
            return None;
        }

        // Get configured paths from cache. This should always succeed because validation
        // happens at startup and the rule is only called when enabled. The unwrap_or_else
        // with panic serves as a defensive assertion.
        let paths = CACHED_PATHS.get_or_init(|| {
            parse_paths_config(config).unwrap_or_else(|e| {
                panic!(
                    "FATAL: invalid or missing configuration for rule 'server_clear_site_data' at runtime: {}",
                    e
                )
            })
        });

        // Check if the current resource path matches any configured path
        let resource_path = extract_path_from_resource(resource);

        // Check if resource path matches any configured path
        let is_logout_path = paths.contains(&resource_path);

        if is_logout_path && !headers.contains_key("clear-site-data") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: format!(
                    "Logout endpoint '{}' should include Clear-Site-Data header to properly clear client-side storage",
                    resource_path
                ),
            })
        } else {
            None
        }
    }
}

/// Extract the path from a resource URL string
fn extract_path_from_resource(resource: &str) -> String {
    // Try to find the path portion of the URL
    // Format: scheme://host:port/path?query#fragment

    // Find where the path starts (after the host)
    if let Some(pos) = resource.find("://") {
        // Skip past the scheme://
        let after_scheme = &resource[pos + 3..];

        // Find the first '/' which marks the start of the path
        if let Some(path_start) = after_scheme.find('/') {
            let path_with_query = &after_scheme[path_start..];

            // Remove query string and fragment
            return path_with_query
                .split('?')
                .next()
                .unwrap_or(path_with_query)
                .split('#')
                .next()
                .unwrap_or(path_with_query)
                .to_string();
        }
    }

    // Fallback: just remove query and fragment
    resource
        .split('?')
        .next()
        .unwrap_or(resource)
        .split('#')
        .next()
        .unwrap_or(resource)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        enable_rule_with_paths, make_test_config_with_enabled_paths_rules, make_test_conn,
        make_test_context,
    };
    use hyper::HeaderMap;

    #[test]
    fn check_response_logout_missing_header() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let cfg = make_test_config_with_enabled_paths_rules(&[(
            "server_clear_site_data",
            &["/logout", "/signout"],
        )]);
        let violation = rule.check_response(
            &client,
            "http://test.com/logout",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        let Some(v) = violation else {
            panic!("Expected violation but got None");
        };
        assert_eq!(v.rule, "server_clear_site_data");
        assert_eq!(v.severity, "warn");
        assert!(v.message.contains("Clear-Site-Data"));
        Ok(())
    }

    #[test]
    fn check_response_logout_present_header() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("clear-site-data", "\"*\"".parse()?);
        let conn = make_test_conn();
        let cfg = make_test_config_with_enabled_paths_rules(&[(
            "server_clear_site_data",
            &["/logout", "/signout"],
        )]);
        let violation = rule.check_response(
            &client,
            "http://test.com/logout",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn check_response_non_logout_path() {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let cfg =
            make_test_config_with_enabled_paths_rules(&[("server_clear_site_data", &["/logout"])]);
        let violation = rule.check_response(
            &client,
            "http://test.com/api/data",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_custom_configured_path() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();

        // Configure custom paths
        let cfg = make_test_config_with_enabled_paths_rules(&[(
            "server_clear_site_data",
            &["/custom/logout", "/auth/signout"],
        )]);

        let violation = rule.check_response(
            &client,
            "http://test.com/custom/logout",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_some());
        Ok(())
    }

    #[test]
    fn check_response_default_signout_path() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let cfg =
            make_test_config_with_enabled_paths_rules(&[("server_clear_site_data", &["/signout"])]);
        let violation = rule.check_response(
            &client,
            "http://test.com/signout",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_some());
        Ok(())
    }

    #[test]
    fn check_response_error_status_ignored() {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 404;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let cfg =
            make_test_config_with_enabled_paths_rules(&[("server_clear_site_data", &["/logout"])]);
        let violation = rule.check_response(
            &client,
            "http://test.com/logout",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_logout_with_query_params() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        enable_rule_with_paths(&mut cfg, "server_clear_site_data", &["/logout"]);
        let violation = rule.check_response(
            &client,
            "http://test.com/logout?redirect=/home",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_some());
        Ok(())
    }

    // Configuration validation tests
    #[test]
    fn validate_config_with_valid_paths() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert(
            "paths".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("/logout".to_string()),
                toml::Value::String("/signout".to_string()),
            ]),
        );
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        assert!(rule.validate_config(&cfg).is_ok());
        Ok(())
    }

    #[test]
    fn validate_config_rejects_missing_config() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let cfg = crate::config::Config::default();
        assert!(rule.validate_config(&cfg).is_err());
        Ok(())
    }

    #[test]
    fn validate_config_rejects_non_table() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::String("/logout".to_string()),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Configuration must be a table"));
        Ok(())
    }

    #[test]
    fn validate_config_rejects_boolean_enable_without_table() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        // User set the rule to true but didn't provide a table with 'paths'
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Boolean(true),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn validate_config_rejects_missing_paths_field() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        let table = toml::map::Map::new(); // Empty table, no "paths" field
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must contain 'paths' field"));
        Ok(())
    }

    #[test]
    fn validate_config_rejects_non_array_paths() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert(
            "paths".to_string(),
            toml::Value::String("/logout".to_string()),
        );
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be an array of strings"));
        Ok(())
    }

    #[test]
    fn validate_config_rejects_empty_paths_array() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("paths".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        Ok(())
    }

    #[test]
    fn validate_config_rejects_non_string_path_items() -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert(
            "paths".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("/logout".to_string()),
                toml::Value::Integer(42), // Invalid: not a string
                toml::Value::String("/signout".to_string()),
            ]),
        );
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let result = rule.validate_config(&cfg);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not a string"));
        assert!(err_msg.contains("index 1"));
        Ok(())
    }
}
