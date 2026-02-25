// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerXContentTypeOptions;

#[derive(Debug, Clone)]
pub struct XContentTypeOptionsConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub content_types: Vec<String>,
}

fn parse_x_content_type_options_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<XContentTypeOptionsConfig> {
    let Some(rule_config) = config.get_rule_config(rule_id) else {
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

    let mut content_types = Vec::new();
    for (idx, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'content_types' item at index {} is not a string", idx)
        })?;
        content_types.push(s.to_ascii_lowercase());
    }

    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    Ok(XContentTypeOptionsConfig {
        enabled,
        content_types,
        severity,
    })
}

impl Rule for ServerXContentTypeOptions {
    type Config = XContentTypeOptionsConfig;

    fn id(&self) -> &'static str {
        "server_x_content_type_options"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_x_content_type_options_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };

        // Get the response's content-type (without parameters)
        let content_type_header =
            crate::helpers::headers::get_header_str(&resp.headers, "content-type").and_then(|s| {
                crate::helpers::headers::parse_semicolon_list(s)
                    .next()
                    .map(|v| v.to_ascii_lowercase())
            });

        if let Some(content_type) = content_type_header {
            if (200..300).contains(&resp.status)
                && config.content_types.contains(&content_type)
                && !resp.headers.contains_key("x-content-type-options")
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Missing X-Content-Type-Options: nosniff header".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::enable_rule;
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

        let config = super::XContentTypeOptionsConfig {
            enabled: true,
            content_types: content_types.iter().map(|s| s.to_string()).collect(),
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
        });

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

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
    #[case("non_table", true, Some("must be a TOML table"))]
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
            "non_table" => {
                cfg.rules.insert(
                    "server_x_content_type_options".to_string(),
                    toml::Value::String("not a table".to_string()),
                );
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
                    "severity".to_string(),
                    toml::Value::String("warn".to_string()),
                );
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

        let res = rule.validate_and_box(&cfg);
        if expect_error {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        } else {
            let boxed = res?;
            let parsed = boxed
                .downcast::<super::XContentTypeOptionsConfig>()
                .unwrap();
            assert_eq!(parsed.content_types, vec!["text/html".to_string()]);
        }
        Ok(())
    }

    #[test]
    fn check_response_with_parameters_matches() -> anyhow::Result<()> {
        let rule = ServerXContentTypeOptions;

        let status = 200;
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

        let config = super::XContentTypeOptionsConfig {
            enabled: true,
            content_types: vec!["text/html".to_string()],
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/html; charset=utf-8",
            )]),

            body_length: None,
        });

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_some());
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = ServerXContentTypeOptions;
        let tx = crate::test_helpers::make_test_transaction();
        let config = super::XContentTypeOptionsConfig {
            enabled: true,
            content_types: vec!["text/html".to_string()],
            severity: crate::lint::Severity::Warn,
        };
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = ServerXContentTypeOptions;
        assert_eq!(rule.id(), "server_x_content_type_options");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
