// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCacheControlTokenValid;

impl Rule for MessageCacheControlTokenValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cache_control_token_valid"
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
                if let Some(msg) = check_cache_control_value(v) {
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
                    if let Some(msg) = check_cache_control_value(v) {
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

fn check_cache_control_value(s: &str) -> Option<String> {
    // Split by top-level commas but ignore commas inside quoted-strings
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
                // empty value allowed
                continue;
            }
            if vpart.starts_with('"') {
                if let Err(e) = crate::helpers::headers::validate_quoted_string(vpart) {
                    return Some(format!("Invalid quoted-string in directive value: {}", e));
                }
            } else {
                // Unquoted value must be a token
                if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                    return Some(format!(
                        "Directive value contains invalid character: '{}'",
                        c
                    ));
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
    #[case("no-cache", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("public, max-age=60", false)]
    #[case("", true)]
    #[case("=abc", true)]
    #[case("ma x-age=1", true)]
    #[case("private=Set Cookie", true)]
    #[case("private=bad@val", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let tx = make_req(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("no-cache", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("public, max-age=60", false)]
    #[case("", true)]
    #[case("=abc", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let tx = make_resp(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[test]
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageCacheControlTokenValid;
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
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
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
    fn response_multiple_headers_merged_are_valid() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("cache-control", "no-cache"),
            ("cache-control", "max-age=60"),
        ]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let tx = make_req("foo=\"bar\"x");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn quoted_value_unterminated_reports_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let tx = make_req("foo=\"unterminated");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_directive_value_is_accepted() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let tx = make_req("foo=");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageCacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", ",max-age=1")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageCacheControlTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageCacheControlTokenValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_cache_control_token_valid".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
