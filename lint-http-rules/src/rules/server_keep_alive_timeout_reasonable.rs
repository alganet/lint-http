// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct ServerKeepAliveConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub max_timeout_seconds: u64,
}

fn parse_keep_alive_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ServerKeepAliveConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a 'max_timeout_seconds' integer value (seconds)",
            rule_id
        )
    })?;

    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let mt = table.get("max_timeout_seconds").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'max_timeout_seconds' integer value in seconds (e.g., 3600)",
            rule_id
        )
    })?;

    let mt_int = mt
        .as_integer()
        .ok_or_else(|| anyhow::anyhow!("'max_timeout_seconds' must be an integer"))?;

    if mt_int <= 0 {
        return Err(anyhow::anyhow!(
            "'max_timeout_seconds' must be a positive integer"
        ));
    }

    Ok(ServerKeepAliveConfig {
        enabled,
        severity,
        max_timeout_seconds: mt_int as u64,
    })
}

pub struct ServerKeepAliveTimeoutReasonable;

impl Rule for ServerKeepAliveTimeoutReasonable {
    fn id(&self) -> &'static str {
        "server_keep_alive_timeout_reasonable"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_keep_alive_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_keep_alive_config(cfg, self.id()).ok()?;
        let Some(resp) = &tx.response else {
            return None;
        };

        // Check for Keep-Alive header (legacy header used by some servers)
        // `Keep-Alive` is not specified by any current HTTP document — RFC 7230 §6.7 was
        // Upgrade, not this. What *is* specified is that connection options are hop-by-hop
        // and named by `Connection`, which is the only sentence this rule can honestly
        // stand on. Its `timeout=` checks encode a de facto convention nobody defines.
        // cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
        for hv in resp.headers.get_all("keep-alive") {
            let Ok(val) = hv.to_str() else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Keep-Alive header value is not valid UTF-8".into(),
                });
            };

            // Split on commas (top-level) like: "timeout=5, max=1000"
            for part in crate::helpers::headers::split_commas_respecting_quotes(val) {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let mut nv = part.splitn(2, '=').map(str::trim);
                let name = nv
                    .next()
                    .expect("splitn always returns at least one item")
                    .to_ascii_lowercase();
                let val_opt = nv.next();
                if name == "timeout" {
                    if val_opt.is_none() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Keep-Alive timeout directive missing value".into(),
                        });
                    }
                    let v = val_opt.expect("checked for none above");
                    // Should be a non-negative integer
                    match v.parse::<u64>() {
                        Ok(sec) => {
                            // Reasonable thresholds: not zero and not unboundedly long
                            if sec == 0 {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Keep-Alive timeout is 0 (immediate); should be > 0"
                                        .into(),
                                });
                            }
                            // If it's larger than configured maximum, flag as unreasonable
                            if sec > config.max_timeout_seconds {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Keep-Alive timeout is unusually large ({sec} seconds); consider lower value"),
                                });
                            }
                        }
                        Err(_) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                "Keep-Alive timeout value '{v}' is not a valid non-negative integer"
                            ),
                            })
                        }
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "When a `Keep-Alive` header includes a `timeout` directive, this rule checks that the `timeout` value is reasonable. The `timeout` value should be a non-negative integer greater than zero and not unreasonably large (e.g., not several hours). `Keep-Alive` is a legacy header used to tune connection persistence; conservative, reasonable values help prevent resource exhaustion on servers and clients."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7230",
                section: Some("6.7"),
                url: "https://www.rfc-editor.org/rfc/rfc7230.html#section-6.7",
                note: "Connection management and the `Keep-Alive` discussion — `Keep-Alive` is a legacy header and must be treated conservatively; this rule validates `timeout` semantics only",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nKeep-Alive: timeout=30, max=100",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nKeep-Alive: timeout=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nKeep-Alive: timeout=999999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nKeep-Alive: timeout=\"60\"   # quoted numeric values are invalid",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerKeepAliveTimeoutReasonable;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("timeout=30"), false)]
    #[case(Some("timeout=0"), true)]
    #[case(Some("timeout=3601"), true)]
    #[case(Some("max=1000"), false)]
    #[case(Some("timeout=bad"), true)]
    #[case(Some("timeout"), true)]
    #[case(Some("timeout=3600"), false)]
    #[case(Some(" timeout =  60 "), false)]
    #[case(Some("timeout=\"60\""), true)]
    #[case(Some("timeout="), true)]
    #[case(None, false)]
    fn check_keep_alive_cases(
        #[case] hv: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerKeepAliveTimeoutReasonable;

        // Build a full config with required 'max_timeout_seconds' (mandatory)
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        full_cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(3600));
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hv {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("keep-alive", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}: got {:?}", hv, v);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {:?}: got {:?}",
                hv,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        let rule = ServerKeepAliveTimeoutReasonable;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("keep-alive", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        full_cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(3600));
                t
            }),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = ServerKeepAliveTimeoutReasonable;
        assert_eq!(rule.id(), "server_keep_alive_timeout_reasonable");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_requires_max_timeout_field() {
        let rule = ServerKeepAliveTimeoutReasonable;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        // Insert a table that lacks max_timeout_seconds -> should error on parse
        cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t
            }),
        );

        let res = rule.validate(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_rules_missing_required_field_fails() {
        // If the rule table is present but missing the required field, overall validation should fail
        let rule = ServerKeepAliveTimeoutReasonable;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t
            }),
        );

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_rejects_non_positive_max_timeout() {
        let rule = ServerKeepAliveTimeoutReasonable;

        // Zero value should be rejected by validate
        let mut cfg_zero = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        cfg_zero.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(0));
                t
            }),
        );
        let res_zero = rule.validate(&cfg_zero);
        assert!(res_zero.is_err());
        let msg = format!("{}", res_zero.unwrap_err());
        assert!(msg.contains("must be a positive integer"));

        // Negative value should also be rejected
        let mut cfg_neg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        cfg_neg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(-1));
                t
            }),
        );
        let res_neg = rule.validate(&cfg_neg);
        assert!(res_neg.is_err());
        let msg2 = format!("{}", res_neg.unwrap_err());
        assert!(msg2.contains("must be a positive integer"));
    }

    #[test]
    fn validate_rules_rejects_zero_max_timeout() {
        let rule = ServerKeepAliveTimeoutReasonable;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(0));
                t
            }),
        );

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ServerKeepAliveTimeoutReasonable;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        full_cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("max_timeout_seconds".into(), toml::Value::Integer(3600));
                t
            }),
        );

        rule.validate(&full_cfg)?;
        // Also ensure validate_rules (overall) will succeed when full config provided
        crate::rules::validate_rules(&full_cfg)?;
        Ok(())
    }
}
