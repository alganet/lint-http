// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct SemanticHeadResponseHeadersMatchGetConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    /// Lowercased header field-names that must match between a previous GET and a HEAD
    pub headers: Vec<String>,
}

fn parse_headers_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<SemanticHeadResponseHeadersMatchGetConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'headers' array listing header field-names to check. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let headers_val = table.get("headers").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'headers' array listing header field-names to validate (e.g., ['etag','content-type','content-length'])",
            rule_id
        )
    })?;

    let arr = headers_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'headers' must be an array of strings (e.g., ['etag','content-type'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'headers' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'headers' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(SemanticHeadResponseHeadersMatchGetConfig {
        enabled,
        severity,
        headers: out,
    })
}

pub struct SemanticHeadResponseHeadersMatchGet;

impl Rule for SemanticHeadResponseHeadersMatchGet {
    type Config = SemanticHeadResponseHeadersMatchGetConfig;

    fn id(&self) -> &'static str {
        "semantic_head_response_headers_match_get"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_headers_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to HEAD responses with a previous GET on the same URI
        if !tx.request.method.eq_ignore_ascii_case("HEAD") {
            return None;
        }

        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let prev = previous?;
        if !prev.request.method.eq_ignore_ascii_case("GET") {
            return None;
        }

        // Ensure previous transaction targets the same resource (stateful match)
        if prev.request.uri != tx.request.uri {
            return None;
        }

        let prev_resp = match &prev.response {
            Some(r) => r,
            None => return None,
        };

        // For each configured header, enforce presence/value equivalence between GET and HEAD
        for name in &config.headers {
            let name_str = name.as_str();

            let prev_has = prev_resp.headers.contains_key(name_str);
            let head_has = resp.headers.contains_key(name_str);

            // RFC-permitted exceptions: omission or presence of these headers on HEAD
            // is allowed (see RFC 9110 §9.3.2 and §8.6 for Content-Length semantics).
            let is_allowed_omission =
                |n: &str| matches!(n, "content-length" | "transfer-encoding" | "vary");

            if prev_has && !head_has {
                if is_allowed_omission(name_str) {
                    // allowed to be omitted on HEAD
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "HEAD response missing header field that GET had: '{}'",
                            name_str
                        ),
                    });
                }
            }

            if head_has && !prev_has {
                if is_allowed_omission(name_str) {
                    // allowed to appear on HEAD even if GET didn't
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "HEAD response includes header field not present on GET: '{}'",
                            name_str
                        ),
                    });
                }
            }

            if prev_has && head_has {
                // Special-case: content-length must match if both present and parseable.
                if name_str.eq_ignore_ascii_case("content-length") {
                    let prev_len = match crate::helpers::headers::validate_content_length(
                        &prev_resp.headers,
                    ) {
                        Ok(Some(n)) => Some(n),
                        _ => None,
                    };
                    let cur_len =
                        match crate::helpers::headers::validate_content_length(&resp.headers) {
                            Ok(Some(n)) => Some(n),
                            _ => None,
                        };

                    if let (Some(p), Some(c)) = (prev_len, cur_len) {
                        if p != c {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Content-Length in HEAD ({}) differs from GET ({})",
                                    c, p
                                ),
                            });
                        }
                    }
                    continue;
                }

                // For list-like headers where ordering may differ, normalize 'Vary' specially
                if name_str.eq_ignore_ascii_case("vary") {
                    let a = crate::helpers::headers::get_header_str(&prev_resp.headers, name_str);
                    let b = crate::helpers::headers::get_header_str(&resp.headers, name_str);
                    if let (Some(av), Some(bv)) = (a, b) {
                        // normalize members to lowercase before sorting/comparison so
                        // token-case differences (e.g. "Accept" vs "accept") do not
                        // cause false positives.
                        let mut a_members: Vec<String> =
                            crate::helpers::headers::parse_list_header(av)
                                .map(|s| s.to_ascii_lowercase())
                                .collect();
                        let mut b_members: Vec<String> =
                            crate::helpers::headers::parse_list_header(bv)
                                .map(|s| s.to_ascii_lowercase())
                                .collect();
                        a_members.sort_unstable();
                        b_members.sort_unstable();
                        if a_members != b_members {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Vary header in HEAD differs from GET: '{}' vs '{}'",
                                    bv, av
                                ),
                            });
                        }
                    }
                    continue;
                }

                // Default: compare UTF-8 header values when available
                let a = crate::helpers::headers::get_header_str(&prev_resp.headers, name_str);
                let b = crate::helpers::headers::get_header_str(&resp.headers, name_str);
                if let (Some(av), Some(bv)) = (a, b) {
                    if av != bv {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Header '{}' value differs between HEAD and GET ('{}' vs '{}')",
                                name_str, bv, av
                            ),
                        });
                    }
                }
                // If either value is not valid UTF-8 we are lenient and do not compare contents.
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn id_and_scope() {
        let r = SemanticHeadResponseHeadersMatchGet;
        assert_eq!(r.id(), "semantic_head_response_headers_match_get");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    fn make_prev_with_headers(pairs: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, pairs);
        tx.request.method = "GET".to_string();
        tx
    }

    fn make_head_with_headers(pairs: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, pairs);
        tx.request.method = "HEAD".to_string();
        tx
    }

    fn make_cfg_with_headers(headers: Vec<&str>) -> SemanticHeadResponseHeadersMatchGetConfig {
        SemanticHeadResponseHeadersMatchGetConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            headers: headers
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    #[test]
    fn matching_get_and_head_ok() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[
            ("etag", "\"v1\""),
            ("content-type", "text/plain"),
            ("content-length", "5"),
        ]);
        let mut head = make_head_with_headers(&[
            ("etag", "\"v1\""),
            ("content-type", "text/plain"),
            ("content-length", "5"),
        ]);
        // ensure URIs match
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["etag", "content-type", "content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn missing_header_on_head_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing header"));
    }

    #[test]
    fn extra_header_on_head_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("x-foo", "bar")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["x-foo"]));
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("includes header field not present"));
    }

    #[test]
    fn content_length_mismatch_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10")]);
        let mut head = make_head_with_headers(&[("content-length", "5")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn content_length_missing_on_head_is_allowed() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn vary_missing_on_head_is_allowed() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "accept-encoding")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["vary"]));
        assert!(v.is_none());
    }

    #[test]
    fn no_previous_does_nothing() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let head = make_head_with_headers(&[("etag", "\"v1\"")]);
        let v = rule.check_transaction(&head, None, &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn previous_with_different_uri_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        // different URIs
        head.request.uri = "/other".parse().unwrap();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn previous_not_get_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.method = "POST".to_string();
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_counts_as_presence() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let mut prev = make_prev_with_headers(&[]);
        // prev has a non-utf8 value for 'etag' — presence should be detected even if value cannot be compared
        let mut hm = prev.response.as_ref().unwrap().headers.clone();
        hm.insert("etag", HeaderValue::from_bytes(&[0xff]).unwrap());
        prev.response = Some(crate::http_transaction::ResponseInfo {
            status: prev.response.as_ref().unwrap().status,
            version: prev.response.as_ref().unwrap().version.clone(),
            headers: hm,
            body_length: None,
        });

        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        // prev had non-utf8 'etag' -> treated as present -> HEAD missing it should be a violation
        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_some());
    }

    #[test]
    fn both_non_utf8_values_are_lenient() {
        // When both GET and HEAD have non-UTF8 header *values*, we treat them as present
        // but we do not attempt to compare their contents — be lenient.
        let rule = SemanticHeadResponseHeadersMatchGet;

        let mut prev = make_prev_with_headers(&[]);
        let mut phm = prev.response.as_ref().unwrap().headers.clone();
        phm.insert("etag", HeaderValue::from_bytes(&[0xff]).unwrap());
        prev.response = Some(crate::http_transaction::ResponseInfo {
            status: prev.response.as_ref().unwrap().status,
            version: prev.response.as_ref().unwrap().version.clone(),
            headers: phm,
            body_length: None,
        });

        let mut head = make_head_with_headers(&[]);
        let mut hhm = head.response.as_ref().unwrap().headers.clone();
        hhm.insert("etag", HeaderValue::from_bytes(&[0xfe]).unwrap());
        head.response = Some(crate::http_transaction::ResponseInfo {
            status: head.response.as_ref().unwrap().status,
            version: head.response.as_ref().unwrap().version.clone(),
            headers: hhm,
            body_length: None,
        });

        head.request.uri = prev.request.uri.clone();

        // Both present but non-UTF8 -> rule should be lenient and not report a violation
        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn header_name_case_insensitive_is_accepted() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("ETAG", "\"v1\"")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn parse_config_requires_headers_array() {
        let cfg = crate::config::Config::default();
        let rule = SemanticHeadResponseHeadersMatchGet;
        let res = rule.validate_and_box(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_headers_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("headers".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let rule = SemanticHeadResponseHeadersMatchGet;
        let res = rule.validate_and_box(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_headers_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let rule = SemanticHeadResponseHeadersMatchGet;
        let res = rule.validate_and_box(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_lowercases_headers_items() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::String("ETag".into())]),
                );
                t
            }),
        );

        let parsed = parse_headers_config(&cfg, "semantic_head_response_headers_match_get")?;
        assert!(parsed.headers.contains(&"etag".to_string()));
        Ok(())
    }

    #[test]
    fn header_value_mismatch_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[("etag", "\"v2\"")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Header 'etag' value differs"));
    }

    #[test]
    fn head_has_unchecked_header_is_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("x-foo", "bar")]);
        head.request.uri = prev.request.uri.clone();

        // 'x-foo' is not in the configured headers list -> should be ignored
        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn transfer_encoding_on_head_allowed_when_prev_missing() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("transfer-encoding", "chunked")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["transfer-encoding"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn transfer_encoding_missing_on_head_is_allowed() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["transfer-encoding"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_prev_invalid_is_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "abc")]);
        let mut head = make_head_with_headers(&[("content-length", "5")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn vary_order_different_but_same_members_ok() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "Accept-Encoding, Accept")]);
        let mut head = make_head_with_headers(&[("vary", "accept, accept-encoding")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["vary"]));
        assert!(v.is_none());
    }

    #[test]
    fn vary_different_members_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "a, b")]);
        let mut head = make_head_with_headers(&[("vary", "a, c")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["vary"]));
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Vary"));
    }

    #[test]
    fn previous_response_missing_is_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.method = "GET".to_string();
        prev.response = None;

        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn prev_non_utf8_and_head_utf8_is_lenient() {
        let rule = SemanticHeadResponseHeadersMatchGet;

        let mut prev = make_prev_with_headers(&[]);
        let mut phm = prev.response.as_ref().unwrap().headers.clone();
        phm.insert("etag", HeaderValue::from_bytes(&[0xff]).unwrap());
        prev.response = Some(crate::http_transaction::ResponseInfo {
            status: prev.response.as_ref().unwrap().status,
            version: prev.response.as_ref().unwrap().version.clone(),
            headers: phm,
            body_length: None,
        });

        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        head.request.uri = prev.request.uri.clone();

        // presence detected, but values are not compared when one side is non-UTF8
        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn multiple_headers_mismatch_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\""), ("content-type", "text/plain")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\""), ("content-type", "text/html")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["etag", "content-type"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("content-type"));
    }

    #[test]
    fn accept_encoding_order_mismatch_reports_violation() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("accept-encoding", "gzip, deflate")]);
        let mut head = make_head_with_headers(&[("accept-encoding", "deflate, gzip")]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["accept-encoding"]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        full_cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::String("etag".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<SemanticHeadResponseHeadersMatchGetConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.headers.contains(&"etag".to_string()));
        Ok(())
    }

    #[test]
    fn parse_config_rejects_headers_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("headers".into(), toml::Value::String("etag".into()));
                t
            }),
        );

        let res = parse_headers_config(&cfg, "semantic_head_response_headers_match_get");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::String("not a table".into()),
        );

        let res = parse_headers_config(&cfg, "semantic_head_response_headers_match_get");
        assert!(res.is_err());
    }

    #[test]
    fn head_missing_response_is_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        // create a HEAD transaction without a response
        let mut head = crate::test_helpers::make_test_transaction();
        head.request.method = "HEAD".to_string();
        head.response = None;
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn multiple_content_length_values_in_prev_are_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10"), ("content-length", "20")]);
        let mut head = make_head_with_headers(&[("content-length", "10")]);
        head.request.uri = prev.request.uri.clone();

        // validate_content_length on prev will error -> rule must be lenient
        let v = rule.check_transaction(
            &head,
            Some(&prev),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn configured_header_missing_in_both_is_ignored() {
        let rule = SemanticHeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = rule.check_transaction(&head, Some(&prev), &make_cfg_with_headers(vec!["etag"]));
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "semantic_head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("etag".into()),
                        toml::Value::String("content-type".into()),
                    ]),
                );
                t
            }),
        );

        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
