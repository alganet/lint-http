// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerClearSiteData;

impl Rule for ServerClearSiteData {
    fn id(&self) -> &'static str {
        "server_clear_site_data"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate_config(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        // Parse and validate the config at startup (inlined to avoid a helper).
        let Some(rule_config) = config.get_rule_config("server_clear_site_data") else {
            return Err(anyhow::anyhow!(
                r#"rule 'server_clear_site_data' requires configuration to be enabled. Example:
[rules.server_clear_site_data]
enabled = true
paths = ["/logout"]"#
            ));
        };

        let table = rule_config.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Configuration must be a table with 'paths' field, e.g., [rules.server_clear_site_data]\npaths = [\"/logout\"]"
            )
        })?;

        let paths_value = table.get("paths").ok_or_else(|| {
            anyhow::anyhow!("Configuration table must contain 'paths' field with array of strings")
        })?;

        let paths_array = paths_value.as_array().ok_or_else(|| {
            anyhow::anyhow!(
                "'paths' field must be an array of strings, e.g., paths = [\"/logout\", \"/signout\"]"
            )
        })?;

        if paths_array.is_empty() {
            return Err(anyhow::anyhow!(
                "'paths' array cannot be empty - provide at least one path or disable the rule"
            ));
        }

        for (idx, item) in paths_array.iter().enumerate() {
            item.as_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "'paths' array item at index {} is not a string: {:?}",
                    idx,
                    item
                )
            })?;
        }

        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &crate::config::Config,
    ) -> Option<Violation> {
        // Only check successful responses
        let Some(resp) = &tx.response else {
            return None;
        };
        let status = resp.status;
        if !(200..300).contains(&status) {
            return None;
        }

        let paths = {
            let Some(rule_config) = config.get_rule_config("server_clear_site_data") else {
                panic!("FATAL: rule 'server_clear_site_data' requires configuration to be enabled at runtime");
            };

            let table = rule_config.as_table().unwrap_or_else(|| {
                panic!(
                    "FATAL: configuration for rule 'server_clear_site_data' must be a TOML table"
                );
            });

            let value = table.get("paths").unwrap_or_else(|| {
                panic!("FATAL: 'paths' field is required and must be an array of strings for rule 'server_clear_site_data'");
            });

            let arr = value.as_array().unwrap_or_else(|| {
                panic!("FATAL: 'paths' must be an array for rule 'server_clear_site_data'");
            });

            if arr.is_empty() {
                panic!("FATAL: 'paths' array cannot be empty for rule 'server_clear_site_data'");
            }

            let mut out = Vec::new();
            for (idx, item) in arr.iter().enumerate() {
                let s = item.as_str().unwrap_or_else(|| {
                    panic!("FATAL: 'paths' item at index {} is not a string", idx)
                });
                out.push(s.to_string());
            }
            out
        };

        // Check if the current resource path matches any configured path
        let resource_path = extract_path_from_resource(&tx.request.uri);

        // Check if resource path matches any configured path
        let is_logout_path = paths.contains(&resource_path);

        if is_logout_path && !resp.headers.contains_key("clear-site-data") {
            Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(config, self.id()),
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
    use crate::test_helpers::make_test_config_with_enabled_paths_rules;
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

        let cfg =
            make_test_config_with_enabled_paths_rules(&[("server_clear_site_data", &config_paths)]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = format!("http://test.com{}", resource_path);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation = rule.check_transaction(&tx, None, &cfg);

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
                let table = toml::map::Map::new(); // Empty table, no "paths" field
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_array" => {
                let mut table = toml::map::Map::new();
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
                table.insert("paths".to_string(), toml::Value::Array(vec![]));
                cfg.rules.insert(
                    "server_clear_site_data".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_string_item" => {
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
            }
            _ => panic!("unknown scenario"),
        }

        let res = rule.validate_config(&cfg);
        if valid {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        }

        Ok(())
    }
}
