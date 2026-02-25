// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct CharsetConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<CharsetConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable charset names. Example in config_example.toml",
            rule_id
        )
    })?;

    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed character set names (e.g., ['utf-8','iso-8859-1'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['utf-8','iso-8859-1'])")
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

    Ok(CharsetConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageCharsetIanaRegistered;

impl Rule for MessageCharsetIanaRegistered {
    type Config = CharsetConfig;

    fn id(&self) -> &'static str {
        "message_charset_iana_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_allowed_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        use crate::helpers::headers::parse_media_type;

        let check_header = |which: &str, val: &str| -> Option<Violation> {
            let parsed = match parse_media_type(val) {
                Ok(p) => p,
                Err(_) => return None, // other rules check Content-Type well-formedness
            };

            if let Some(params) = parsed.params {
                for raw in params.split(';') {
                    let p = raw.trim();
                    if p.is_empty() {
                        continue;
                    }
                    if let Some(eq) = p.find('=') {
                        let (name, value) = p.split_at(eq);
                        let name = name.trim();
                        let value = value[1..].trim(); // skip '='
                        if name.eq_ignore_ascii_case("charset") {
                            if value.is_empty() {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                });
                            }

                            // Quoted-string handling: allow escaped characters via helper
                            let mut value_owned: Option<String> = None;
                            if value.starts_with('"') {
                                match crate::helpers::headers::unescape_quoted_string(value) {
                                    Ok(u) => value_owned = Some(u),
                                    Err(e) => {
                                        return Some(Violation {
                                            rule: MessageCharsetIanaRegistered.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Invalid Content-Type in {}: 'charset' quoted-string invalid: {}",
                                                which, e
                                            ),
                                        })
                                    }
                                }
                            } else {
                                // validate token characters
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(value)
                                {
                                    return Some(Violation {
                                        rule: MessageCharsetIanaRegistered.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid Content-Type in {}: charset contains invalid character '{}'",
                                            which, c
                                        ),
                                    });
                                }
                            }
                            let value = value_owned.as_deref().unwrap_or(value);

                            if value.is_empty() {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                });
                            }

                            if !config.allowed.contains(&value.to_ascii_lowercase()) {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Unrecognized charset '{}' in {} header",
                                        value, which
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            None
        };

        // Check request Content-Type
        if let Some(s) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-type")
        {
            if let Some(v) = check_header("request", s) {
                return Some(v);
            }
        }
        // Check response Content-Type
        if let Some(resp) = &tx.response {
            if let Some(s) = crate::helpers::headers::get_header_str(&resp.headers, "content-type")
            {
                if let Some(v) = check_header("response", s) {
                    return Some(v);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> CharsetConfig {
        CharsetConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "utf-8".to_string(),
                "iso-8859-1".to_string(),
                "us-ascii".to_string(),
            ],
        }
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/html; charset=ISO-8859-1"), false)]
    #[case(Some("text/plain; charset=us-ascii"), false)]
    #[case(Some("text/plain"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"UTF-8\""), false)]
    #[case(Some("text/plain; charset=\"\""), true)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ct {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"broken"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ct {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("utf-8".into()));
                t
            }),
        );
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::String("not-a-table".into()),
        );
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        // If Content-Type fails to parse, this rule should return None (other rules handle well-formedness)
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn charset_name_case_and_spacing_ok() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; CHARSET = UTF-8",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_response() {
        // A parameter without an '=' should be ignored, producing no violation
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_request() {
        // Same as response, but for requests
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn trailing_semicolon_is_ignored() {
        // Trailing semicolons should not cause errors
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8;",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn duplicate_charset_param_reports_violation() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8; charset=unknown-charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn parse_allowed_config_missing_rule_errors() {
        let cfg = crate::config::Config::default();
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("requires configuration") || msg.contains("missing"));
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("utf-8".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<CharsetConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"utf-8".to_string()));
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(b"text/plain; charset=\xff").unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("content-type", bad);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageCharsetIanaRegistered;
        assert_eq!(rule.id(), "message_charset_iana_registered");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
