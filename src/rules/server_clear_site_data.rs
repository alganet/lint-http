// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerClearSiteData;

#[derive(Debug, Clone)]
pub struct ClearSiteDataConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub paths: Vec<String>,
}

/// Parse and validate paths configuration for this rule
fn parse_paths_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ClearSiteDataConfig> {
    // Require a configuration table for this rule. If none is provided, return an error
    // since this rule is not enabled by default and configuration is required to enable it.
    let Some(rule_config) = config.get_rule_config(rule_id) else {
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

    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    Ok(ClearSiteDataConfig {
        enabled,
        paths,
        severity,
    })
}

impl Rule for ServerClearSiteData {
    type Config = ClearSiteDataConfig;

    fn id(&self) -> &'static str {
        "server_clear_site_data"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_paths_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only check successful responses
        let Some(resp) = &tx.response else {
            return None;
        };
        let status = resp.status;
        if !(200..300).contains(&status) {
            return None;
        }

        // Check if the current resource path matches any configured path
        let resource_path = extract_path_from_resource(&tx.request.uri);

        // Check if resource path matches any configured path
        let is_logout_path = config.paths.contains(&resource_path);

        if is_logout_path && !resp.headers.contains_key("clear-site-data") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
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
    use rstest::rstest;

    #[rstest]
    #[case("/logout", vec![], vec!["/logout", "/signout"], 200, true, Some("Clear-Site-Data"))]
    #[case("/logout", vec![("clear-site-data","\"*\"")], vec!["/logout", "/signout"], 200, false, None)]
    #[case("/api/data", vec![], vec!["/logout"], 200, false, None)]
    #[case("/custom/logout", vec![], vec!["/custom/logout", "/auth/signout"], 200, true, Some("Clear-Site-Data"))]
    #[case("/signout", vec![], vec!["/signout"], 200, true, Some("Clear-Site-Data"))]
    #[case("/logout", vec![], vec!["/logout"], 404, false, None)]
    #[case("/logout?redirect=/home", vec![], vec!["/logout"], 200, true, Some("Clear-Site-Data"))]
    fn check_response_cases(
        #[case] resource_path: &str,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] config_paths: Vec<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
        #[case] expected_message_contains: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerClearSiteData;

        let config = super::ClearSiteDataConfig {
            enabled: true,
            paths: config_paths.iter().map(|s| s.to_string()).collect(),
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = format!("http://test.com{}", resource_path);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation = rule.check_transaction(&tx, None, &config);

        if expect_violation {
            let Some(v) = violation else {
                panic!("Expected violation but got None");
            };
            assert_eq!(v.rule, "server_clear_site_data");
            assert_eq!(v.severity, crate::lint::Severity::Warn);
            if let Some(msg) = expected_message_contains {
                assert!(v.message.contains(msg));
            }
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    // Configuration validation tests
    #[rstest]
    #[case("valid", true, None)]
    #[case("missing_config", false, Some("requires configuration"))]
    #[case("non_table", false, Some("Configuration must be a table"))]
    #[case("boolean_enable", false, None)]
    #[case("missing_paths", false, Some("must contain 'paths' field"))]
    #[case("non_array", false, Some("must be an array of strings"))]
    #[case("empty_array", false, Some("cannot be empty"))]
    #[case("non_string_item", false, Some("not a string"))]
    fn validate_config_cases(
        #[case] scenario: &str,
        #[case] valid: bool,
        #[case] expected_substring: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerClearSiteData;
        let mut cfg = crate::config::Config::default();

        match scenario {
            "valid" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "severity".to_string(),
                    toml::Value::String("warn".to_string()),
                );
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
            }
            "missing_config" => {
                // keep default config (no rule table)
            }
            "non_table" => {
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::String("/logout".to_string()),
                );
            }
            "boolean_enable" => {
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Boolean(true),
                );
            }
            "missing_paths" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "paths".to_string(),
                    toml::Value::String("/logout".to_string()),
                );
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Table(table),
                );
            }
            "empty_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert("paths".to_string(), toml::Value::Array(vec![]));
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_string_item" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
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
            }
            _ => panic!("unknown scenario"),
        }

        let res = rule.validate_and_box(&cfg);
        if valid {
            let boxed = res?;
            let parsed = boxed.downcast::<super::ClearSiteDataConfig>().unwrap();
            assert_eq!(
                parsed.paths,
                vec!["/logout".to_string(), "/signout".to_string()]
            );
        } else {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        }

        Ok(())
    }
}
