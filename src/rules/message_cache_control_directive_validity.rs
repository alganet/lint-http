// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCacheControlDirectiveValidity;

impl Rule for MessageCacheControlDirectiveValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cache_control_directive_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Apply to both request and response messages
        for header_val in tx.request.headers.get_all("cache-control").iter() {
            if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                if v.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Cache-Control header must not be empty".into(),
                    });
                }
                if let Some(msg) = check_cache_control_directives(v) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Cache-Control header in request: {}", msg),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Cache-Control header contains non-UTF8 value".into(),
                });
            }
        }

        if let Some(resp) = &tx.response {
            for header_val in resp.headers.get_all("cache-control").iter() {
                if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                    if v.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Cache-Control header must not be empty".into(),
                        });
                    }
                    if let Some(msg) = check_cache_control_directives(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Cache-Control header in response: {}", msg),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Cache-Control header contains non-UTF8 value".into(),
                    });
                }
            }
        }

        None
    }
}

fn check_cache_control_directives(s: &str) -> Option<String> {
    for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
        let member = member.trim();
        if member.is_empty() {
            return Some("Empty directive in Cache-Control header".into());
        }

        // directive = token [ "=" ( token / quoted-string ) ]
        let mut kv = member.splitn(2, '=');
        let name = kv.next().unwrap().trim();
        if name.is_empty() {
            return Some(format!(
                "Empty directive name in Cache-Control member: '{}'",
                member
            ));
        }

        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(format!(
                "Directive name contains invalid character: '{}'",
                c
            ));
        }

        if let Some(vpart) = kv.next() {
            let vpart = vpart.trim();
            if vpart.is_empty() {
                // empty value allowed for directives that accept an empty value
                continue;
            }

            // Specific directive checks
            let lname = name.to_ascii_lowercase();
            match lname.as_str() {
                "max-age" | "s-maxage" => {
                    // must be a non-negative integer
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                        // If it contains non-token chars it's invalid (no quotes allowed here)
                        return Some(format!(
                            "{} value contains invalid character: '{}'",
                            name, c
                        ));
                    }
                    if vpart.chars().any(|ch| !ch.is_ascii_digit()) {
                        return Some(format!("{} must be a non-negative integer", name));
                    }
                    // parse to ensure numeric range
                    if vpart.parse::<u64>().is_err() {
                        return Some(format!("{} value is not a valid integer", name));
                    }
                }
                "private" | "no-cache" => {
                    // optional list of field-names (comma-separated tokens) or quoted-string
                    if vpart.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(vpart) {
                            return Some(format!("Invalid quoted-string in {} value: {}", name, e));
                        }
                        // strip quotes and split on commas
                        let inner = &vpart[1..vpart.len() - 1];
                        for field in inner.split(',') {
                            let f = field.trim();
                            if f.is_empty() {
                                return Some(format!("Empty field-name in {} value", name));
                            }
                            if let Some(c) = crate::helpers::token::find_invalid_token_char(f) {
                                return Some(format!(
                                    "{} includes invalid field-name character: '{}'",
                                    name, c
                                ));
                            }
                        }
                    } else {
                        // unquoted: allow single token or comma-separated tokens
                        for part in vpart.split(',') {
                            let p = part.trim();
                            if p.is_empty() {
                                return Some(format!("Empty field-name in {} value", name));
                            }
                            if let Some(c) = crate::helpers::token::find_invalid_token_char(p) {
                                return Some(format!(
                                    "{} includes invalid field-name character: '{}'",
                                    name, c
                                ));
                            }
                        }
                    }
                }
                _ => {
                    // For other directives, accept token or quoted-string and ensure token syntax if unquoted
                    if vpart.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(vpart) {
                            return Some(format!(
                                "Invalid quoted-string in directive {} value: {}",
                                name, e
                            ));
                        }
                    } else if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                        return Some(format!(
                            "Directive {} value contains invalid character: '{}'",
                            name, c
                        ));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", val)]);
        tx
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("cache-control", val)]),
            body_length: None,
        });
        tx
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=Foo", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    #[case("no-cache=field1,field2", false)]
    #[case("no-cache=\"field1, field2\"", false)]
    #[case("public, max-age=60", false)]
    #[case("foo=bar", false)]
    #[case("max-age=abc", true)]
    #[case("max-age=-1", true)]
    #[case("max-age=1.5", true)]
    #[case("s-maxage=1.5", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("max-age=1!", true)]
    #[case("private=Set Cookie", true)]
    #[case("private=\"Set Cookie\"", true)]
    #[case("private=bad@val", true)]
    #[case("private=,", true)]
    #[case("private=\",\"", true)]
    #[case("ma x=1", true)]
    #[case("custom=\"unterminated", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    #[case("foo=bar", false)]
    #[case("max-age=abc", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("custom=\"unterminated", true)]
    #[case("max-age=1!", true)]
    #[case("private=,", true)]
    #[case("ma x=1", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_resp(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[test]
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("cache-control", "no-cache"),
            ("cache-control", "max-age=60"),
        ]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageCacheControlDirectiveValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", ",max-age=1")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageCacheControlDirectiveValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_cache_control_directive_validity".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn foo_empty_value_allowed() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("foo=");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn foo_quoted_value_allowed() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("foo=\"bar\"");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn directive_value_invalid_token() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("foo=bad@val");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn max_age_too_large_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("max-age=18446744073709551616");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_directive_name_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("=bar");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn private_quoted_empty_field_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("private=\"field1,,field3\"");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn private_quoted_invalid_field_char_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("private=\"field1,bad@field\"");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn response_non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageCacheControlDirectiveValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn whitespace_around_name_value_accepted() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req(" max-age = 3600 ");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("foo=\"bar\"x");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_directives_unquoted_comma_accepted() -> anyhow::Result<()> {
        let rule = MessageCacheControlDirectiveValidity;
        let tx = make_req("foo=bar,baz");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }
}
