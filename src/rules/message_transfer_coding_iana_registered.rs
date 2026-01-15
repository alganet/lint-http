// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct TransferCodingConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<TransferCodingConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable transfer-codings. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed transfer-coding tokens (e.g., ['chunked','gzip','deflate'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['chunked','gzip'])")
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

    Ok(TransferCodingConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageTransferCodingIanaRegistered;

impl Rule for MessageTransferCodingIanaRegistered {
    type Config = TransferCodingConfig;

    fn id(&self) -> &'static str {
        "message_transfer_coding_iana_registered"
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
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // check a list-style header value (Transfer-Encoding or TE) against allowed list
        let check_value = |hdr_name: &str, val: &str, allowed: &[String]| -> Option<Violation> {
            for part in crate::helpers::headers::parse_list_header(val) {
                let token = part.split(';').next().unwrap().trim();
                // TE allows the special value 'trailers'
                if hdr_name.eq_ignore_ascii_case("TE") && token.eq_ignore_ascii_case("trailers") {
                    continue;
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in {} header", c, hdr_name),
                    });
                }
                if !allowed.contains(&token.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: format!(
                            "Unrecognized transfer-coding '{}' in {} header",
                            token, hdr_name
                        ),
                    });
                }
            }
            None
        };
        // Check Transfer-Encoding header in response and request (if any)
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "transfer-encoding")
            {
                if let Some(v) = check_value("Transfer-Encoding", val, &config.allowed) {
                    return Some(v);
                }
            }
        }

        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "transfer-encoding")
        {
            if let Some(v) = check_value("Transfer-Encoding", val, &config.allowed) {
                return Some(v);
            }
        }

        // Check TE header in requests (TE is a request header)
        if let Some(val) = crate::helpers::headers::get_header_str(&tx.request.headers, "te") {
            if let Some(v) = check_value("TE", val, &config.allowed) {
                return Some(v);
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

    fn make_cfg() -> TransferCodingConfig {
        TransferCodingConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "chunked".to_string(),
                "gzip".to_string(),
                "deflate".to_string(),
            ],
        }
    }

    #[rstest]
    #[case(Some("chunked"), false)]
    #[case(Some("gzip"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("chunked, x-custom"), true)]
    #[case(Some("chunked; param=1"), false)]
    #[case(None, false)]
    fn check_transfer_encoding_response_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = te {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("trailers"), false)]
    #[case(Some("gzip;q=1.0"), false)]
    #[case(Some("x-custom;q=0.1"), true)]
    #[case(Some("x!bad"), true)]
    #[case(None, false)]
    fn check_te_request_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = te {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_token_in_transfer_encoding_is_reported() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x@bad")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_transfer_coding_iana_registered");
        assert!(
            v.message.contains("Invalid token")
                || v.message.contains("Unrecognized transfer-coding")
        );
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "transfer-encoding",
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        let mut tx2 = crate::test_helpers::make_test_transaction();
        let mut hm2 = hyper::HeaderMap::new();
        hm2.insert("te", HeaderValue::from_bytes(b"\xff").unwrap());
        tx2.request.headers = hm2;
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTransferCodingIanaRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn parse_config_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered")?;
        assert_eq!(parsed.allowed, vec!["x-custom".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
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

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("chunked".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<TransferCodingConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"chunked".to_string()));
        Ok(())
    }

    #[test]
    fn request_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&full_cfg, "message_transfer_coding_iana_registered")?;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "x-custom;q=0.5")]);

        let v = rule.check_transaction(&tx, None, &parsed);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&full_cfg, "message_transfer_coding_iana_registered")?;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x-custom")]);

        let v = rule.check_transaction(&tx, None, &parsed);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn unrecognized_transfer_coding_message_and_severity() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = TransferCodingConfig {
            enabled: true,
            severity: crate::lint::Severity::Error,
            allowed: vec!["chunked".to_string()],
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x-foo")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.severity, crate::lint::Severity::Error);
        assert_eq!(
            v.message,
            "Unrecognized transfer-coding 'x-foo' in Transfer-Encoding header"
        );
        Ok(())
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Integer(1),
        );
        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("chunked".into()));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[rstest]
    #[case(Some("chunked"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("chunked, x-custom"), true)]
    #[case(Some("chunked; param=1"), false)]
    #[case(None, false)]
    fn check_transfer_encoding_request_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = te {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn te_trailers_with_unknown_reports_violation() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "trailers, x-custom")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("Unrecognized transfer-coding")
                || v.message.contains("Invalid token")
        );
        Ok(())
    }

    #[test]
    fn invalid_token_in_transfer_encoding_request_is_reported() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x@bad")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid token"));
        Ok(())
    }
}
