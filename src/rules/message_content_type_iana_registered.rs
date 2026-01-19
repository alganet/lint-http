// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct ContentTypeConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ContentTypeConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable media-types or patterns. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed media-types (e.g., ['text/plain','application/json','image/*','+json'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "'allowed' must be an array of strings (e.g., ['text/plain','application/json'])"
        )
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

    Ok(ContentTypeConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageContentTypeIanaRegistered;

impl Rule for MessageContentTypeIanaRegistered {
    type Config = ContentTypeConfig;

    fn id(&self) -> &'static str {
        "message_content_type_iana_registered"
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
        let check_media_type =
            |hdr_name: &str, val: &str, allowed: &Vec<String>| -> Option<Violation> {
                // Parse media-type; if it fails, let other rules (well-formed) report it.
                let parsed = match crate::helpers::headers::parse_media_type(val) {
                    Ok(p) => p,
                    Err(_) => return None,
                };
                let t = parsed.type_.to_ascii_lowercase();
                let s = parsed.subtype.to_ascii_lowercase();
                let full = format!("{}/{}", t, s);

                for pat in allowed {
                    if pat == "*/*" || pat == &full {
                        return None;
                    }
                    if pat.ends_with("/*") {
                        // type/* form
                        if let Some(idx) = pat.find('/') {
                            let ptype = &pat[..idx];
                            if ptype == t {
                                return None;
                            }
                        }
                    }
                    if let Some(suff) = pat.strip_prefix('+') {
                        // +suffix form: match subtype suffix
                        if s.ends_with(suff) {
                            return None;
                        }
                    }
                }

                Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Unrecognized media type '{}' in {} header", full, hdr_name),
                })
            };

        // Check request Content-Type
        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-type")
        {
            if let Some(v) = check_media_type("Content-Type", val, &config.allowed) {
                return Some(v);
            }
        }

        // Check response Content-Type
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type")
            {
                if let Some(v) = check_media_type("Content-Type", val, &config.allowed) {
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
    use rstest::rstest;

    fn make_cfg() -> ContentTypeConfig {
        ContentTypeConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "text/plain".to_string(),
                "application/json".to_string(),
                "image/*".to_string(),
                "+json".to_string(),
            ],
        }
    }

    #[rstest]
    #[case(Some("text/plain"), false)]
    #[case(Some("application/json; charset=utf-8"), false)]
    #[case(Some("application/ld+json"), false)]
    #[case(Some("image/png"), false)]
    #[case(Some("application/vnd.example"), true)]
    #[case(Some("text/x-custom"), true)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ct {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
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
    #[case(Some("text/plain"), false)]
    #[case(Some("application/vnd.custom+json; foo=bar"), false)]
    #[case(Some("application/x-cms"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ct {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
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
    fn malformed_content_type_is_ignored() {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn wildcard_allowed_accepts_any() {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = ContentTypeConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec!["*/*".to_string()],
        };
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/vnd.unknown",
        )]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn case_insensitive_allowed_is_parsed() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_type_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("IMAGE/*".into())]),
                );
                t
            }),
        );
        let parsed = parse_allowed_config(&cfg, "message_content_type_iana_registered")?;
        assert!(parsed.allowed.contains(&"image/*".to_string()));
        Ok(())
    }

    #[test]
    fn suffix_matches_json_variants() {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);
        assert!(rule.check_transaction(&tx1, None, &cfg).is_none());

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/ld+json",
        )]);
        assert!(rule.check_transaction(&tx2, None, &cfg).is_none());
    }

    #[test]
    fn violation_message_is_meaningful() {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/x-custom")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_content_type_iana_registered");
        assert!(v.message.contains("Content-Type"));
        assert!(v.message.contains("text/x-custom"));
    }

    #[test]
    fn config_parse_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_type_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom/type".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_content_type_iana_registered")?;
        assert!(parsed.allowed.contains(&"x-custom/type".to_string()));
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_type_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_content_type_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_iana_registered",
        ]);
        cfg.rules.insert(
            "message_content_type_iana_registered".into(),
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

        let res = parse_allowed_config(&cfg, "message_content_type_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageContentTypeIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_content_type_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("text/plain".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<ContentTypeConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"text/plain".to_string()));
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageContentTypeIanaRegistered;
        let cfg = make_cfg();

        // Non-utf8 response header value should be ignored and produce no violation
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-type",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        // Non-utf8 request header value should be ignored
        let mut tx2 = crate::test_helpers::make_test_transaction();
        let mut hm2 = hyper::HeaderMap::new();
        hm2.insert(
            "content-type",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx2.request.headers = hm2;
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentTypeIanaRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
