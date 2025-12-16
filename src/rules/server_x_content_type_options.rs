// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::config_cache::RuleConfigCache;
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

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

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
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

        let Some(resp) = &tx.response else {
            return None;
        };

        // Get the response's content-type (without parameters)
        let content_type_header = resp.headers.get("content-type").and_then(|hv| {
            hv.to_str()
                .ok()
                .map(|s| s.split(';').next().unwrap_or(s).trim().to_ascii_lowercase())
        });

        if let Some(content_type) = content_type_header {
            if (200..300).contains(&resp.status)
                && content_types.contains(&content_type)
                && !resp.headers.contains_key("x-content-type-options")
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
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
    use crate::test_helpers::{
        enable_rule, make_test_config_with_content_types, make_test_conn, make_test_context,
    };
    use rstest::rstest;

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], vec!["text/html"], true, Some("Missing X-Content-Type-Options: nosniff header"))]
    #[case(200, vec![("content-type", "text/javascript"), ("x-content-type-options", "nosniff")], vec!["text/javascript"], false, None)]
    #[case(404, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(101, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "image/png")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "text/html; charset=utf-8")], vec!["text/html"], true, Some("Missing X-Content-Type-Options: nosniff header"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] content_types: Vec<&str>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (_client, _state) = make_test_context();
        let conn = make_test_conn();
        let cfg = make_test_config_with_content_types(&content_types);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation = rule.check_transaction(&tx, &conn, &_state, &cfg);

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case("missing_table", true, None)]
    #[case("missing_field", true, None)]
    #[case("non_array", true, None)]
    #[case("non_string_item", true, Some("not a string"))]
    #[case("empty_array", true, Some("cannot be empty"))]
    #[case("valid", false, None)]
    fn validate_config_cases(
        #[case] scenario: &str,
        #[case] expect_error: bool,
        #[case] expected_substring: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let mut cfg = crate::config::Config::default();

        match scenario {
            "missing_table" => {
                // No rule table at all
            }
            "missing_field" => {
                enable_rule(&mut cfg, "server_x_content_type_options");
            }
            "non_array" => {
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
            }
            "non_string_item" => {
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
            }
            "empty_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert("content_types".to_string(), toml::Value::Array(vec![]));
                cfg.rules.insert(
                    "server_x_content_type_options".to_string(),
                    toml::Value::Table(table),
                );
            }
            "valid" => {
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
            }
            _ => panic!("unknown scenario"),
        }

        let res = rule.validate_config(&cfg);
        if expect_error {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        } else {
            res?;
            let cached = CACHED_CONTENT_TYPES.get_or_init(|| {
                panic!("the cache should have been initialized in validate_config")
            });
            assert_eq!(cached, vec!["text/html".to_string()]);
        }
        Ok(())
    }

    #[test]
    fn check_response_with_parameters_matches() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;
        let (_client, _state) = make_test_context();
        let status = 200;
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

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/html; charset=utf-8",
            )]),
        });

        let violation = rule.check_transaction(&tx, &conn, &_state, &cfg);
        assert!(violation.is_some());
        Ok(())
    }
}
