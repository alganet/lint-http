// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Pragma` header directives must follow directive = token ["=" ( token / quoted-string )]
/// and be syntactically valid. This rule flags invalid tokens, malformed quoted-strings,
/// non-UTF8 header values, and empty header/member values. (RFC 9110 §8.2)
pub struct MessagePragmaTokenValid;

impl Rule for MessagePragmaTokenValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_pragma_token_valid"
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
        // Validate request headers
        for header_val in tx.request.headers.get_all("pragma").iter() {
            if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                if v.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Pragma header must not be empty".into(),
                    });
                }
                if let Some(msg) = check_pragma_value(v) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Pragma header in request: {}", msg),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Pragma header contains non-UTF8 value".into(),
                });
            }
        }

        // Validate response headers too (historical usage)
        if let Some(resp) = &tx.response {
            for header_val in resp.headers.get_all("pragma").iter() {
                if let Some(v) = header_val.to_str().ok().map(|s| s.trim()) {
                    if v.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Pragma header must not be empty".into(),
                        });
                    }
                    if let Some(msg) = check_pragma_value(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Pragma header in response: {}", msg),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Pragma header contains non-UTF8 value".into(),
                    });
                }
            }
        }

        None
    }
}

fn check_pragma_value(s: &str) -> Option<String> {
    for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
        let member = member.trim();
        if member.is_empty() {
            return Some("Empty directive in Pragma header".into());
        }

        let mut kv = member.splitn(2, '=');
        let name = kv.next().unwrap().trim();
        if name.is_empty() {
            return Some(format!(
                "Empty directive name in Pragma member: '{}'",
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
                continue;
            }
            if vpart.starts_with('"') {
                if let Err(e) = crate::helpers::headers::validate_quoted_string(vpart) {
                    return Some(format!("Invalid quoted-string in directive value: {}", e));
                }
            } else if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                return Some(format!(
                    "Directive value contains invalid character: '{}'",
                    c
                ));
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
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("pragma", val)]);
        tx
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("pragma", val)]),

            body_length: None,
        });
        tx
    }

    #[rstest]
    #[case("no-cache", false)]
    #[case("no-cache, foo=bar", false)]
    #[case("no-cache, token=\"quoted,comma\"", false)]
    #[case("", true)]
    #[case("=abc", true)]
    #[case("bad token", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessagePragmaTokenValid;
        let tx = make_req(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}', got: {:?}",
                value,
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[rstest]
    #[case("no-cache", false)]
    #[case("no-cache, foo=bar", false)]
    #[case("", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessagePragmaTokenValid;
        let tx = make_resp(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}', got: {:?}",
                value,
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessagePragmaTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("pragma", bad);
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessagePragmaTokenValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_pragma_token_valid".into(),
            toml::Value::Table(table),
        );
        let _ = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = MessagePragmaTokenValid;
        assert_eq!(r.id(), "message_pragma_token_valid");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }
}
