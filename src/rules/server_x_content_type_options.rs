// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::config_cache::RuleConfigCache;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

pub struct ServerXContentTypeOptions;

static CACHED_CONTENT_TYPES: RuleConfigCache<Vec<String>> = RuleConfigCache::new();

fn parse_x_content_type_options_config(
    config: &crate::config::Config,
) -> anyhow::Result<Vec<String>> {
    let Some(rule_config) = config.get_rule_config("server_x_content_type_options") else {
        return Err(anyhow::anyhow!(
            "rule 'server_x_content_type_options' requires configuration to be enabled. Example:\n[rules.server_x_content_type_options]\nenabled = true\ncontent_types = [\"text/html\", \"application/json\"]"
        ));
    };

    let table = rule_config.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Configuration for rule 'server_x_content_type_options' must be a TOML table with 'content_types' array"
        )
    })?;

    let value = table.get("content_types").ok_or_else(|| {
        anyhow::anyhow!("'content_types' field is required and must be an array of strings")
    })?;

    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'content_types' must be an array"))?;
    if arr.is_empty() {
        return Err(anyhow::anyhow!("'content_types' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (idx, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'content_types' item at index {} is not a string", idx)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(out)
}

impl Rule for ServerXContentTypeOptions {
    fn id(&self) -> &'static str {
        "server_x_content_type_options"
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        // Only evaluate when status is 2xx and the response Content-Type matches one of the configured types
        let content_types = CACHED_CONTENT_TYPES.get_or_init(|| {
            parse_x_content_type_options_config(_config).unwrap_or_else(|e| {
                panic!("FATAL: invalid or missing configuration for rule 'server_x_content_type_options' at runtime: {}", e);
            })
        });

        // Get the response's content-type (without parameters)
        let content_type_header = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_ascii_lowercase());

        if let Some(content_type) = content_type_header {
            if (200..300).contains(&status)
                && content_types.contains(&content_type)
                && !headers.contains_key("x-content-type-options")
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: "warn".into(),
                    message: "Missing X-Content-Type-Options: nosniff header".into(),
                });
            }
        }
        None
    }

    fn validate_config(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        let parsed = parse_x_content_type_options_config(config)?;
        CACHED_CONTENT_TYPES.set(parsed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{enable_rule, make_test_conn, make_test_context};
    use hyper::HeaderMap;

    #[test]
    fn check_response_200_missing_header() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse()?);
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Missing X-Content-Type-Options: nosniff header".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_response_200_present_header() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/javascript".parse()?);
        headers.insert("x-content-type-options", "nosniff".parse()?);
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/javascript".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let violation = rule.check_response(
            &client,
            "http://test.com",
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
    fn check_response_404_missing_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 404;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().unwrap());
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_101_missing_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 101;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().unwrap());
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_non_matching_content_type() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "image/png".parse()?);
        let conn = make_test_conn();

        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );

        let violation = rule.check_response(
            &client,
            "http://test.com",
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
    fn validate_config_missing_table_errors() {
        let rule = ServerXContentTypeOptions;
        let cfg = crate::config::Config::default();
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_missing_content_types_field_errors() {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();
        enable_rule(&mut cfg, "server_x_content_type_options");
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_non_array_errors() {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::String("text/html".to_string()),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_non_string_items_errors() {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::Integer(5)]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_empty_array_errors() {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("content_types".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_valid_config_ok() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );

        rule.validate_config(&cfg)?;

        // Assert that the cached content types were set and lowercased
        let cached = CACHED_CONTENT_TYPES
            .get_or_init(|| panic!("the cache should have been initialized in validate_config"));
        assert_eq!(cached, vec!["text/html".to_string()]);

        Ok(())
    }

    #[test]
    fn check_response_with_parameters_matches() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html; charset=utf-8".parse()?);
        let conn = make_test_conn();
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        cfg.rules.insert(
            "server_x_content_type_options".to_string(),
            toml::Value::Table(table),
        );

        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &cfg,
        );
        assert!(violation.is_some());
        Ok(())
    }
}
