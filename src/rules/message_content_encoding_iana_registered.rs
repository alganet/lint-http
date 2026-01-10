// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct ContentEncodingConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ContentEncodingConfig> {
    // Base required fields (enabled + severity)
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    // Allowed list is REQUIRED for this rule. It must be an array of strings.
    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable content-codings. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed content-coding tokens (e.g., ['gzip','br','deflate'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['gzip','br'])")
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

    Ok(ContentEncodingConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageContentEncodingIanaRegistered;

impl Rule for MessageContentEncodingIanaRegistered {
    type Config = ContentEncodingConfig;

    fn id(&self) -> &'static str {
        "message_content_encoding_iana_registered"
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
        // Helper to check a single header value against allowed list
        let check_value = |hdr_name: &str, val: &str, allowed: &Vec<String>| -> Option<Violation> {
            for part in crate::helpers::headers::parse_list_header(val) {
                // Split off any parameters (e.g., gzip;q=0.8)
                let token = part.split(';').next().unwrap().trim();
                if token == "*" {
                    // wildcard is acceptable in Accept-Encoding
                    continue;
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: "message_content_encoding_iana_registered".into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in {} header", c, hdr_name),
                    });
                }
                if !allowed.contains(&token.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: "message_content_encoding_iana_registered".into(),
                        severity: config.severity,
                        message: format!(
                            "Unrecognized content-coding '{}' in {} header",
                            token, hdr_name
                        ),
                    });
                }
            }
            None
        };

        // Check response Content-Encoding
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-encoding")
            {
                if let Some(v) = check_value("Content-Encoding", val, &config.allowed) {
                    return Some(v);
                }
            }
        }

        // Check request Accept-Encoding
        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "accept-encoding")
        {
            if let Some(v) = check_value("Accept-Encoding", val, &config.allowed) {
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

    fn make_cfg() -> ContentEncodingConfig {
        ContentEncodingConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "gzip".to_string(),
                "br".to_string(),
                "deflate".to_string(),
                "zstd".to_string(),
            ],
        }
    }

    #[rstest]
    #[case(Some("gzip"), false)]
    #[case(Some("br"), false)]
    #[case(Some("gZiP"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("gzip, x-custom"), true)]
    #[case(Some("gzip;q=0.8"), false)]
    #[case(Some("*"), false)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ce: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
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
    #[case(Some("gzip"), false)]
    #[case(Some("br;q=1.0"), false)]
    #[case(Some("x-custom;q=0.1"), true)]
    #[case(Some("*, gzip"), false)]
    #[case(Some("x!bad"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ae: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
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
    fn config_parse_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
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

        let parsed = parse_allowed_config(&cfg, "message_content_encoding_iana_registered")?;
        assert_eq!(parsed.allowed, vec!["x-custom".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_content_encoding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
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

        let res = parse_allowed_config(&cfg, "message_content_encoding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        // When the rule is enabled but 'allowed' key missing, parsing should fail
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        let res = parse_allowed_config(&cfg, "message_content_encoding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn validate_and_box_fails_when_allowed_missing() {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        let res = rule.validate_and_box(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
            toml::Value::String("not-a-table".into()),
        );
        let res = parse_allowed_config(&cfg, "message_content_encoding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("gzip".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<ContentEncodingConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"gzip".to_string()));
        Ok(())
    }

    #[test]
    fn invalid_token_in_content_encoding_is_reported() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x!bad")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_content_encoding_iana_registered");
        // Message should indicate either an invalid token or an unrecognized coding
        assert!(
            v.message.contains("Invalid token")
                || v.message.contains("Unrecognized content-coding")
        );
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        // Non-utf8 response header value should be ignored and produce no violation
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-encoding",
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        // Non-utf8 request header value should be ignored
        let mut tx2 = crate::test_helpers::make_test_transaction();
        let mut hm2 = hyper::HeaderMap::new();
        hm2.insert("accept-encoding", HeaderValue::from_bytes(b"\xff").unwrap());
        tx2.request.headers = hm2;
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_none());
    }
    #[test]
    fn request_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
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

        let parsed = parse_allowed_config(&full_cfg, "message_content_encoding_iana_registered")?;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "x-custom;q=0.5")]);

        let v = rule.check_transaction(&tx, None, &parsed);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
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

        let parsed = parse_allowed_config(&full_cfg, "message_content_encoding_iana_registered")?;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x-custom")]);

        let v = rule.check_transaction(&tx, None, &parsed);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn trailing_commas_and_whitespace_are_ignored() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip, ")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "gzip, ")]);
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_none());
        Ok(())
    }

    #[test]
    fn content_encoding_with_parameters_is_supported() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip; param=1")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn iana_registry_entries_are_accepted() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = ContentEncodingConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "aes128gcm",
                "br",
                "compress",
                "dcb",
                "dcz",
                "deflate",
                "exi",
                "gzip",
                "identity",
                "pack200-gzip",
                "x-compress",
                "x-gzip",
                "zstd",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        };

        for coding in &cfg.allowed {
            // response
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(
                &[("content-encoding", coding.as_str())],
            );
            let v = rule.check_transaction(&tx, None, &cfg);
            assert!(
                v.is_none(),
                "coding {} produced violation in response",
                coding
            );

            // request
            let mut tx2 = crate::test_helpers::make_test_transaction();
            tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
                "accept-encoding",
                coding.as_str(),
            )]);
            let v2 = rule.check_transaction(&tx2, None, &cfg);
            assert!(
                v2.is_none(),
                "coding {} produced violation in request",
                coding
            );
        }
        Ok(())
    }

    #[test]
    fn parse_config_accepts_uppercase_allowed_entries() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_encoding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_encoding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("GZIP".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_content_encoding_iana_registered")?;
        assert_eq!(parsed.allowed, vec!["gzip".to_string()]);
        Ok(())
    }

    #[test]
    fn unrecognized_content_coding_message_and_severity() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = ContentEncodingConfig {
            enabled: true,
            severity: crate::lint::Severity::Error,
            allowed: vec!["gzip".to_string()],
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x-foo")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.severity, crate::lint::Severity::Error);
        assert_eq!(
            v.message,
            "Unrecognized content-coding 'x-foo' in Content-Encoding header"
        );
        Ok(())
    }

    #[test]
    fn invalid_token_message_exact() -> anyhow::Result<()> {
        let rule = MessageContentEncodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // use '@' which is not a tchar to trigger the invalid-token branch
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x@bad")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.message, "Invalid token '@' in Content-Encoding header");
        Ok(())
    }
}
