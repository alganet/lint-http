// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessagePreferHeaderValid;

impl Rule for MessagePreferHeaderValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_prefer_header_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Applies to requests only
        let req = &tx.request;

        for val in req.headers.get_all("prefer").iter() {
            let s = match val.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Prefer header contains non-UTF8 value".into(),
                    })
                }
            };

            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Prefer header must not be empty".into(),
                });
            }

            // Split by top-level commas into preference members
            for member in crate::helpers::headers::parse_list_header(s) {
                // Each member: preference = token ["=" word] *( ";" [ parameter ] )
                // Split off semicolon-separated params first
                let mut parts = member.split(';').map(|p| p.trim());
                let first = parts.next().unwrap_or("");
                if first.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Empty preference token in Prefer header: '{}'", member),
                    });
                }

                // first may be token or token=BWS word
                let mut kv = first.splitn(2, '=');
                let name = kv.next().unwrap().trim();
                if name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Empty preference token in Prefer header: '{}'", member),
                    });
                }
                if let Some(ch) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Preference token contains invalid character: '{}'", ch),
                    });
                }

                if let Some(valpart) = kv.next() {
                    let valpart = valpart.trim();
                    if valpart.is_empty() {
                        // empty value is allowed (treated as empty-string)
                    } else if valpart.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(valpart) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid quoted-string in Prefer parameter value: {}",
                                    e
                                ),
                            });
                        }
                    } else {
                        // token value
                        if let Some(ch) = crate::helpers::token::find_invalid_token_char(valpart) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Preference parameter value contains invalid character: '{}'",
                                    ch
                                ),
                            });
                        }
                    }
                }

                // Validate optional parameters: token [ = word ]
                for param in parts {
                    if param.is_empty() {
                        continue;
                    }

                    let mut pnv = param.splitn(2, '=');
                    let pname = pnv.next().unwrap().trim();
                    if pname.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Empty parameter name in Prefer header: '{}'", member),
                        });
                    }

                    if let Some(ch) = crate::helpers::token::find_invalid_token_char(pname) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Preference parameter name contains invalid character: '{}'",
                                ch
                            ),
                        });
                    }

                    if let Some(pv) = pnv.next() {
                        let pv = pv.trim();
                        if pv.is_empty() {
                            continue;
                        }

                        if pv.starts_with('"') {
                            if let Err(e) = crate::helpers::headers::validate_quoted_string(pv) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid quoted-string in Prefer parameter value: {}",
                                        e
                                    ),
                                });
                            }
                        } else if let Some(ch) = crate::helpers::token::find_invalid_token_char(pv)
                        {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Preference parameter value contains invalid character: '{}'",
                                    ch
                                ),
                            });
                        }
                    }
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

    fn make_req(pref: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("prefer", pref)]);
        tx
    }

    #[rstest]
    #[case("respond-async", false)]
    #[case("return=representation", false)]
    #[case("return=minimal; foo=\"some parameter\"", false)]
    #[case("handling=lenient, wait=100", false)]
    #[case("", true)]
    #[case("=abc", true)]
    #[case("\"quoted\"", true)]
    #[case("foo=bad@", true)]
    #[case("f@o=1", true)]
    #[case("return=minimal; =foo", true)]
    #[case("return=minimal; n@me=1", true)]
    #[case("return=minimal; foo=", false)]
    #[case("return=minimal; foo=\"bad", true)]
    #[case("return=bad@", true)]
    #[case("return=", false)]
    // Additional cases to increase coverage and exercise edge conditions
    #[case("respond-async,", false)]
    #[case("respond-async,,wait=100", false)]
    #[case("return=minimal; foo", false)]
    #[case("return=minimal; foo=\"a\\\"b\"", false)]
    #[case("respond-async; ; wait=100", false)]
    #[case("return=minimal ; foo = bar", false)]
    #[case("respond-async; foo=bar; baz=", false)]
    #[case("return=minimal; ;", false)]
    fn check_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessagePreferHeaderValid;
        let tx = make_req(value);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
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
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = MessagePreferHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("prefer", "respond-async, wait=100"),
            ("prefer", "handling=lenient"),
        ]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessagePreferHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("prefer", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        // A member that starts with a semicolon or is empty should trigger an empty preference token violation
        let rule = MessagePreferHeaderValid;
        let tx = make_req(";foo");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Empty preference token"));
        Ok(())
    }

    #[test]
    fn invalid_token_char_messages_include_char() -> anyhow::Result<()> {
        let rule = MessagePreferHeaderValid;
        let tx = make_req("f@o=1");
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("'@'"));

        let tx2 = make_req("return=minimal; foo=bad@");
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());
        let msg2 = v2.unwrap().message;
        assert!(msg2.contains("'@'"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessagePreferHeaderValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_prefer_header_valid".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = MessagePreferHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
