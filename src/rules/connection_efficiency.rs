// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::config_cache::RuleConfigCache;
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

/// Cached runtime configuration for the rule
static CACHED_CFG: RuleConfigCache<ConnectionEfficiencyConfig> = RuleConfigCache::new();

#[derive(Clone)]
struct ConnectionEfficiencyConfig {
    pub min_connections: u64,
    pub min_reuse_ratio: f64,
}

/// Parse and validate the rule's TOML configuration. This rule requires an explicit
/// `[rules.connection_efficiency]` table. If the table is missing or invalid, return an error.
fn parse_connection_efficiency_config(
    config: &crate::config::Config,
    // Require a configuration table for this rule. If none is provided, return an error
    // mirroring other validation patterns in the rules module.
    //
    // Example:
    // [rules.connection_efficiency]
    // enabled = true
    // min_connections = 5
    // min_reuse_ratio = 1.1
) -> anyhow::Result<ConnectionEfficiencyConfig> {
    let Some(rule_config) = config.get_rule_config("connection_efficiency") else {
        return Err(anyhow::anyhow!(
            "Configuration for rule 'connection_efficiency' is missing - rule requires a [rules.connection_efficiency] table with 'min_connections' and 'min_reuse_ratio'"
        ));
    };

    let table = rule_config.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Configuration for rule 'connection_efficiency' must be a TOML table with numeric fields 'min_connections' and 'min_reuse_ratio'"
        )
    })?;

    // Parse min_connections (required)
    let min_connections: i64 = match table.get("min_connections") {
        Some(v) => v
            .as_integer()
            .ok_or_else(|| anyhow::anyhow!("'min_connections' must be an integer"))?,
        None => {
            return Err(anyhow::anyhow!(
                "'min_connections' is required and must be an integer"
            ))
        }
    };

    if min_connections < 1 {
        return Err(anyhow::anyhow!("'min_connections' must be >= 1"));
    }

    // Parse min_reuse_ratio (required)
    let min_reuse_ratio = match table.get("min_reuse_ratio") {
        Some(v) => {
            if let Some(f) = v.as_float() {
                f
            } else if let Some(i) = v.as_integer() {
                i as f64
            } else {
                return Err(anyhow::anyhow!(
                    "'min_reuse_ratio' must be a number (integer or float)"
                ));
            }
        }
        None => {
            return Err(anyhow::anyhow!(
                "'min_reuse_ratio' is required and must be a number (integer or float)"
            ))
        }
    };

    if min_reuse_ratio <= 0.0 {
        return Err(anyhow::anyhow!("'min_reuse_ratio' must be greater than 0"));
    }

    Ok(ConnectionEfficiencyConfig {
        min_connections: min_connections as u64,
        min_reuse_ratio,
    })
}

pub struct ConnectionEfficiency;

impl Rule for ConnectionEfficiency {
    fn id(&self) -> &'static str {
        "connection_efficiency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn validate_config(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        let parsed = parse_connection_efficiency_config(config)?;
        CACHED_CFG.set(parsed);
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let client = &tx.client;
        let count = state.get_connection_count(client);

        let cfg = CACHED_CFG.get_or_init(|| {
            parse_connection_efficiency_config(_config).unwrap_or_else(|e| {
                panic!(
                    "FATAL: invalid or missing configuration for rule 'connection_efficiency' at runtime: {}",
                    e
                )
            })
        });

        if count > cfg.min_connections {
            if let Some(efficiency) = state.get_connection_efficiency(client) {
                // Efficiency = requests / connections.
                // If efficiency is close to 1.0, it means 1 request per connection.
                if efficiency < cfg.min_reuse_ratio {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!(
                            "Low connection efficiency ({:.2} reqs/conn). Client is not reusing connections (Keep-Alive).",
                            efficiency
                        ),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{enable_rule, make_test_context};
    use rstest::rstest;

    #[test]
    fn check_request_no_violation_initially() {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();

        // First request, no history
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(5));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(1.1));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.client = client.clone();
        let violation = rule.check_transaction(&tx, &state, &cfg);
        assert!(violation.is_none());
    }

    #[rstest]
    #[case(6, 1, 5, 1.1, true)]
    #[case(1, 10, 5, 1.1, false)]
    #[case(6, 1, 10, 1.1, false)]
    #[case(6, 1, 5, 2.0, true)]
    fn check_request_efficiency_scenarios(
        #[case] connections: usize,
        #[case] requests_per_connection: usize,
        #[case] min_connections: i64,
        #[case] min_reuse_ratio: f64,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();

        // Simulate connections and transactions using a pattern specified by case
        for _i in 0..connections {
            state.record_connection(&client);
            for _ in 0..requests_per_connection {
                let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
                tx.client = client.clone();
                tx.request.uri = "http://test.com".to_string();
                state.record_transaction(&tx);
            }
        }
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "min_connections".to_string(),
            toml::Value::Integer(min_connections),
        );
        table.insert(
            "min_reuse_ratio".to_string(),
            toml::Value::Float(min_reuse_ratio),
        );
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        let violation = rule.check_transaction(&tx, &state, &cfg);

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.ok_or_else(|| anyhow::anyhow!("expected violation"))?;
            assert_eq!(v.rule, "connection_efficiency");
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }

    #[test]
    fn validate_config_missing_keys_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        // Enable the rule but don't provide required numeric fields
        enable_rule(&mut cfg, "connection_efficiency");

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_valid_config_ok() -> anyhow::Result<()> {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(5));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(1.1));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        rule.validate_config(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_config_min_connections_zero_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(0));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(1.1));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_min_connections_negative_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(-1));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(1.1));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_min_reuse_ratio_zero_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(5));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(0.0));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_min_reuse_ratio_negative_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(5));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(-1.0));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_non_numeric_types_errors() {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "min_connections".to_string(),
            toml::Value::String("five".to_string()),
        );
        table.insert(
            "min_reuse_ratio".to_string(),
            toml::Value::String("one.point.one".to_string()),
        );
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_config_integer_min_reuse_ratio_ok() -> anyhow::Result<()> {
        let rule = ConnectionEfficiency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(5));
        // Use integer for min_reuse_ratio, should be accepted
        table.insert("min_reuse_ratio".to_string(), toml::Value::Integer(2));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        rule.validate_config(&cfg)?;
        Ok(())
    }

    #[test]
    fn check_request_runtime_panic_on_missing_keys() {
        // When the rule is enabled but missing numeric fields, check_request should panic
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();

        let mut cfg = crate::config::Config::default();
        enable_rule(&mut cfg, "connection_efficiency");

        let res = std::panic::catch_unwind(|| {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.client = client.clone();
            let _ = rule.check_transaction(&tx, &state, &cfg);
        });
        assert!(res.is_err());
    }

    #[test]
    fn check_request_min_connections_one_trigger() -> anyhow::Result<()> {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();

        // Simulate 2 connections with 1 request each (Efficiency = 1.0)
        for _i in 0..2 {
            state.record_connection(&client);
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.client = client.clone();
            tx.request.uri = "http://test.com".to_string();
            state.record_transaction(&tx);
        }

        // Config: min_connections = 1, so rule should trigger on 2 connections
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("min_connections".to_string(), toml::Value::Integer(1));
        table.insert("min_reuse_ratio".to_string(), toml::Value::Float(1.1));
        cfg.rules.insert(
            "connection_efficiency".to_string(),
            toml::Value::Table(table),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        let violation = rule.check_transaction(&tx, &state, &cfg);

        assert!(violation.is_some());
        Ok(())
    }

    #[test]
    fn validate_config_missing_table_errors() {
        let rule = ConnectionEfficiency;
        let cfg = crate::config::Config::default();
        let res = rule.validate_config(&cfg);
        assert!(res.is_err());
    }
}
