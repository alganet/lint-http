// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct AltSvcProtocolConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<AltSvcProtocolConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable protocol identifiers. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed Alt-Svc protocol tokens (e.g., ['h2','h3'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['h2','h3'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(AltSvcProtocolConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct ServerAltSvcProtocolIanaRegistered;

impl Rule for ServerAltSvcProtocolIanaRegistered {
    fn id(&self) -> &'static str {
        "server_alt_svc_protocol_iana_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_allowed_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_allowed_config(cfg, self.id()).ok()?;
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("alt-svc").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Alt-Svc header contains non-UTF8 value".into(),
                    })
                }
            };

            for entry in crate::helpers::headers::parse_list_header(s) {
                // protocol=authority[; params]
                let proto_part = entry.split(';').next().unwrap().trim();
                if proto_part.is_empty() {
                    // syntax rule will catch this; be conservative here
                    continue;
                }

                let eq_idx = proto_part.find('=');
                if eq_idx.is_none() {
                    // syntax rule will catch missing '='; skip here
                    continue;
                }

                let (protocol, _auth_raw) = proto_part.split_at(eq_idx.expect("checked above"));
                let protocol = protocol.trim();
                if protocol.is_empty() {
                    continue;
                }

                if let Some(c) = crate::helpers::token::find_invalid_token_char(protocol) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in Alt-Svc protocol id", c),
                    });
                }

                if !config.allowed.contains(&protocol.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Unrecognized Alt-Svc protocol identifier '{}' (not in allowed list)",
                            protocol
                        ),
                    });
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc Protocol IANA-Registered")
    }

    fn description(&self) -> &'static str {
        "Validate `Alt-Svc` response header protocol identifiers. Each `protocol` token (the left-hand side of `protocol=authority`) should be a valid `token` and should be IANA-registered or explicitly allowed via configuration (e.g., `h2`, `h3`). This prevents advertising unsupported or mistyped protocol identifiers to clients."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html) — Alternative Services (syntax and semantics)",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Alt-Svc: h2=\":443\"; ma=2592000\nAlt-Svc: h3=example.com:8443\nAlt-Svc: H2=example.com:443  # protocol tokens are case-insensitive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Alt-Svc: xproto=example.com:443   # protocol not in allowlist\nAlt-Svc: h@=example.com:443      # invalid protocol token character",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerAltSvcProtocolIanaRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "server_alt_svc_protocol_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(
                        ["h2", "h3", "h2c", "ws", "wss"]
                            .iter()
                            .map(|p| toml::Value::String(p.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("h2=\":443\"; ma=2592000"), false)]
    #[case(Some("h3=example.com:8443"), false)]
    #[case(Some("H2=example.com:443"), false)]
    #[case(Some("xproto=example.com:443"), true)]
    #[case(Some("h@=example.com:443"), true)]
    #[case(Some("h2=example.com:443, xproto=example.com:443"), true)]
    #[case(Some(","), false)]
    #[case(Some("h2example.com:443"), false)]
    #[case(None, false)]
    fn check_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerAltSvcProtocolIanaRegistered;
        let cfg = make_cfg();

        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn multiple_header_values_reports_invalid_protocol() {
        let rule = ServerAltSvcProtocolIanaRegistered;
        let cfg = make_cfg();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("alt-svc", "h2=example.com:443"),
                ("alt-svc", "xproto=example.com:443"),
            ],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Unrecognized Alt-Svc protocol identifier"));
    }

    #[test]
    fn missing_eq_is_ignored_and_no_panic() {
        let rule = ServerAltSvcProtocolIanaRegistered;
        let cfg = make_cfg();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2example.com:443")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // syntax rule will report missing '='; this rule should be conservative and not panic or report
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerAltSvcProtocolIanaRegistered;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("alt-svc", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            trailers: None,
        });

        let cfg = make_cfg();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_alt_svc_protocol_iana_registered");
        cfg.rules.insert(
            "server_alt_svc_protocol_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("h2".into()),
                        toml::Value::String("h3".into()),
                    ]),
                );
                t
            }),
        );

        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerAltSvcProtocolIanaRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
