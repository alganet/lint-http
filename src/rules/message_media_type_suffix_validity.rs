// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageMediaTypeSuffixValidity;

#[derive(Debug, Clone)]
pub struct MessageMediaTypeSuffixConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<MessageMediaTypeSuffixConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config
        .get_rule_config(rule_id)
        .ok_or_else(|| anyhow::anyhow!("missing configuration for '{}'", rule_id))?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
                anyhow::anyhow!(
                    "Rule '{}' requires an 'allowed' array listing known structured-syntax suffixes (e.g., ['json','xml'])",
                    rule_id
                )
            })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['json','xml'])")
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

    Ok(MessageMediaTypeSuffixConfig {
        enabled,
        severity,
        allowed: out,
    })
}

impl Rule for MessageMediaTypeSuffixValidity {
    type Config = MessageMediaTypeSuffixConfig;

    fn id(&self) -> &'static str {
        "message_media_type_suffix_validity"
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
        let check_media = |hdr_name: &str, val: &str| -> Option<Violation> {
            let parsed = match crate::helpers::headers::parse_media_type(val) {
                Ok(p) => p,
                Err(_) => return None, // let well-formed rules handle syntax
            };
            let subtype = parsed.subtype.trim();
            if let Some(suffix) = crate::helpers::headers::media_type_subtype_suffix(subtype) {
                let suffix = suffix.to_ascii_lowercase();
                if suffix.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Media type '{}/{}' in {} has empty structured suffix",
                            parsed.type_, parsed.subtype, hdr_name
                        ),
                    });
                }

                if !config.allowed.contains(&suffix) {
                    return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Unrecognized structured syntax suffix '+{}' in media type '{}/{}' (header '{}')",
                                    suffix, parsed.type_, parsed.subtype, hdr_name
                                ),
                            });
                }
            }
            None
        };

        // Check request Content-Type
        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-type")
        {
            if let Some(v) = check_media("Content-Type", val) {
                return Some(v);
            }
        }

        // Check Accept header members
        if let Some(ah) = crate::helpers::headers::get_header_str(&tx.request.headers, "accept") {
            for part in ah.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                if let Some(v) = check_media("Accept", p) {
                    return Some(v);
                }
            }
        }

        // Check response Content-Type
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type")
            {
                if let Some(v) = check_media("Content-Type", val) {
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

    fn make_cfg() -> MessageMediaTypeSuffixConfig {
        MessageMediaTypeSuffixConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "json".to_string(),
                "xml".to_string(),
                "ber".to_string(),
                "der".to_string(),
                "fastinfoset".to_string(),
                "wbxml".to_string(),
                "exi".to_string(),
            ],
        }
    }

    #[rstest]
    fn valid_application_ld_json() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/ld+json")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_none());
    }

    #[rstest]
    fn invalid_content_type_suffix() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/vnd.example+unknown")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+unknown"));
    }

    #[rstest]
    fn accept_header_with_bad_suffix_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "application/vnd.foo+xml; q=0.8, application/bar+nope",
        )]);
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+nope"));
    }

    #[rstest]
    fn detect_empty_suffix_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/foo+")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty structured suffix"));
    }

    #[rstest]
    fn uppercase_suffix_is_accepted() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/ld+JSON")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_none());
    }

    #[rstest]
    fn malformed_media_type_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_none());
    }

    #[rstest]
    fn request_content_type_bad_suffix_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/vnd.foo+unknown",
        )]);
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+unknown"));
    }

    #[rstest]
    fn request_content_type_uppercase_suffix_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/example+JSON",
        )]);
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_none());
    }

    #[rstest]
    fn accept_header_case_insensitive_suffix_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "application/vnd.foo+JSON; q=0.8, text/html",
        )]);
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(&tx, None, &make_cfg());
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageMediaTypeSuffixValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn parse_config_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_media_type_suffix_validity",
        ]);
        cfg.rules.insert(
            "message_media_type_suffix_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("ldjson".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_media_type_suffix_validity")?;
        assert_eq!(parsed.allowed, vec!["ldjson".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_media_type_suffix_validity",
        ]);
        cfg.rules.insert(
            "message_media_type_suffix_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_media_type_suffix_validity");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_media_type_suffix_validity",
        ]);
        cfg.rules.insert(
            "message_media_type_suffix_validity".into(),
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

        let res = parse_allowed_config(&cfg, "message_media_type_suffix_validity");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_media_type_suffix_validity",
        ]);
        let res = parse_allowed_config(&cfg, "message_media_type_suffix_validity");
        assert!(res.is_err());
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageMediaTypeSuffixValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_media_type_suffix_validity",
        ]);
        full_cfg.rules.insert(
            "message_media_type_suffix_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("json".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<MessageMediaTypeSuffixConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.allowed.contains(&"json".to_string()));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_media_type_suffix_validity");
        // Add required 'allowed' key
        if let Some(toml::Value::Table(t)) = cfg.rules.get_mut("message_media_type_suffix_validity")
        {
            t.insert(
                "allowed".to_string(),
                toml::Value::Array(vec![toml::Value::String("json".into())]),
            );
        }
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
