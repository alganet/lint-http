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
    fn id(&self) -> &'static str {
        "message_media_type_suffix_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
        let check_media = |hdr_name: &str, val: &str| -> Option<Violation> {
            let parsed = match crate::helpers::headers::parse_media_type(val) {
                Ok(p) => p,
                Err(_) => return None, // let well-formed rules handle syntax
            };
            let subtype = parsed.subtype.trim();
            // cite(RFC 6838 § 4.2.8): "Media types that make use of a named structured syntax SHOULD use the appropriate registered "+suffix" for that structured syntax"
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

        // Every field line, and decoded from the raw octets. `get_header_str`
        // does neither: it returns the first value and gives up entirely on a
        // value `to_str` refuses. Both losses are silent here, and both hide the
        // exact thing this rule looks for —
        //
        //   Content-Type: application/json
        //   Content-Type: application/vnd.x+bogus
        //
        // reported nothing, and so did a bad suffix sitting next to a parameter
        // carrying obs-text, which is legal in a `quoted-string`.
        // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
        let values = |headers: &hyper::HeaderMap, name: &'static str| -> Vec<String> {
            headers
                .get_all(name)
                .iter()
                .map(|hv| String::from_utf8_lossy(hv.as_bytes()).into_owned())
                .collect()
        };

        for val in values(&tx.request.headers, "content-type") {
            if let Some(v) = check_media("Content-Type", &val) {
                return Some(v);
            }
        }

        // Accept is a list, so each member is checked; the field lines are
        // recombined by the same comma the list uses, which is why they need no
        // separate handling here.
        //
        // Quote-aware, because a comma inside a quoted parameter value is not a
        // list separator. A raw `split(',')` cut such a value apart and then
        // read the pieces as media types, so text that merely looks like one
        // was reported as a real media type with a bad suffix:
        //
        //   Accept: application/json;p="a,foo/bar+bogus"
        //   -> Unrecognized structured syntax suffix '+bogus"' in 'foo/bar+bogus"'
        //
        // The message even carried the stray quote, which is the tell.
        for ah in values(&tx.request.headers, "accept") {
            for part in crate::helpers::headers::split_commas_respecting_quotes(&ah) {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                if let Some(v) = check_media("Accept", p) {
                    return Some(v);
                }
            }
        }

        if let Some(resp) = &tx.response {
            for val in values(&resp.headers, "content-type") {
                if let Some(v) = check_media("Content-Type", &val) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Media Type Suffix Validity")
    }

    fn description(&self) -> &'static str {
        "This rule flags media types (in `Content-Type` or `Accept`) whose subtype ends with a `+suffix` that is not a recognized structured-syntax suffix. Unknown or misspelled suffixes may lead to incorrect parsing or interoperability issues."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6838",
                section: Some("4.2.8"),
                url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8",
                note: "Structured Syntax Name Suffixes",
            },
            crate::rules::SpecRef {
                spec: "IANA Media Type Structured Suffixes",
                section: None,
                url: "https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml",
                note: "IANA Structured Syntax Suffix registry",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Type: application/ld+json\nContent-Type: application/xml\nAccept: application/vnd.example+json; q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— unknown suffix"),
                snippet: "Content-Type: application/vnd.example+unknown\nAccept: application/bar+nope",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageMediaTypeSuffixValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // A comma inside a quoted parameter value is not a list separator, so the
    // text after it is not a media type and must not be judged as one.
    #[case("application/json;p=\"a,foo/bar+bogus\"", false)]
    #[case("application/json;p=\"x,y/z+nope\", text/html", false)]
    // Real members are still each checked, before and after a quoted comma.
    #[case("text/html, application/vnd.x+bogus", true)]
    #[case("application/json;p=\"a,b\", application/vnd.x+bogus", true)]
    #[case("application/ld+json, text/html", false)]
    fn accept_members_split_on_real_commas_only(#[case] accept: &str, #[case] expect: bool) {
        let rule = MessageMediaTypeSuffixValidity;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", accept)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect, "{accept} -> {v:?}");
    }

    #[rstest]
    // A bad suffix on a second Content-Type line: `get_header_str` stopped at
    // the first and reported nothing.
    #[case(&["application/json", "application/vnd.x+bogus"], true)]
    #[case(&["application/vnd.x+bogus", "application/json"], true)]
    #[case(&["application/json", "application/ld+json"], false)]
    fn every_content_type_line_is_checked(#[case] values: &[&str], #[case] expect: bool) {
        let rule = MessageMediaTypeSuffixValidity;
        let cfg = make_cfg();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect, "{values:?} -> {v:?}");
    }

    #[rstest]
    // obs-text is legal in a quoted parameter value, so these are well-formed
    // media types whose suffix still has to be judged. `to_str` refused them
    // and the rule went silent.
    #[case(b"application/vnd.x+bogus; p=\"\xe4\"", true)]
    #[case(b"application/ld+json; p=\"\xe4\"", false)]
    fn obs_text_does_not_hide_the_suffix(#[case] raw: &[u8], #[case] expect: bool) {
        use hyper::header::HeaderValue;
        let rule = MessageMediaTypeSuffixValidity;
        let cfg = make_cfg();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-type", HeaderValue::from_bytes(raw).unwrap());
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(raw)
        );
    }

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "message_media_type_suffix_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("json".into()),
                        toml::Value::String("xml".into()),
                        toml::Value::String("ber".into()),
                        toml::Value::String("der".into()),
                        toml::Value::String("fastinfoset".into()),
                        toml::Value::String("wbxml".into()),
                        toml::Value::String("exi".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    fn valid_application_ld_json() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/ld+json")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn invalid_content_type_suffix() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/vnd.example+unknown")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn malformed_media_type_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let rule = MessageMediaTypeSuffixValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
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
    fn validate_parses_config() -> anyhow::Result<()> {
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

        let arc = parse_allowed_config(&full_cfg, rule.id())?;
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
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
