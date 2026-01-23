// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRefreshHeaderSyntaxValid;

impl Rule for MessageRefreshHeaderSyntaxValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_refresh_header_syntax_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // Refresh is a response header (non-standard but commonly seen)
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("refresh").iter() {
            let s = match hv.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Refresh header contains non-UTF8 value".into(),
                    })
                }
            };

            // Common error: comma-separated values (multi-value in single field) is invalid
            if s.contains(',') {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Refresh header value '{}' must not be a comma-separated list",
                        s
                    ),
                });
            }

            let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
            if parts.is_empty() || parts[0].is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Refresh header value '{}' is invalid: missing delta-seconds",
                        s
                    ),
                });
            }

            // First part must be a non-negative integer (delta-seconds)
            if parts[0].parse::<u64>().is_err() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Refresh delta-seconds '{}' is not a non-negative integer",
                        parts[0]
                    ),
                });
            }

            // Optional parameters: only support `url=` parameter (case-insensitive)
            for param in parts.iter().skip(1) {
                if param.is_empty() {
                    continue;
                }
                let lower = param.to_ascii_lowercase();
                if lower.starts_with("url=") {
                    // Extract value after '=' preserving original case for URI checks
                    let idx = param.find('=').unwrap();
                    let v = param[(idx + 1)..].trim();
                    if v.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Refresh 'url' parameter requires a non-empty value".into(),
                        });
                    }
                    // Validate URI-like value using existing helpers
                    if crate::helpers::uri::contains_whitespace(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Refresh url '{}' contains whitespace", v),
                        });
                    }
                    if let Some(msg) = crate::helpers::uri::check_percent_encoding(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Refresh url '{}' invalid percent-encoding: {}",
                                v, msg
                            ),
                        });
                    }
                    if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Refresh url '{}' invalid scheme: {}", v, msg),
                        });
                    }
                    continue;
                }

                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Unrecognized Refresh parameter: '{}'", param),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&[("refresh", "5")], false)]
    #[case(&[("refresh", "0")], false)]
    #[case(&[("refresh", "10; url=/new")], false)]
    #[case(&[("refresh", "10; url=http://example/")], false)]
    #[case(&[("refresh", "10;URL=/x")], false)]
    #[case(&[("refresh", "bad")], true)]
    #[case(&[("refresh", "10; url=")], true)]
    #[case(&[("refresh", "10; foo=bar")], true)]
    #[case(&[("refresh", "10, 20")], true)]
    fn cases(#[case] hdrs: &[(&str, &str)], #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageRefreshHeaderSyntaxValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, hdrs);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}", hdrs);
        } else {
            assert!(v.is_none(), "unexpected violation for {:?}: {:?}", hdrs, v);
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageRefreshHeaderSyntaxValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 value");
        hm.insert("refresh", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn multiple_header_fields_all_valid() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageRefreshHeaderSyntaxValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("refresh", HeaderValue::from_static("5"));
        hm.append("refresh", HeaderValue::from_static("10; url=/x"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_one_invalid_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageRefreshHeaderSyntaxValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("refresh", HeaderValue::from_static("5"));
        hm.append("refresh", HeaderValue::from_static("bad"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn whitespace_only_value_reports_missing_delta_seconds() -> anyhow::Result<()> {
        let rule = MessageRefreshHeaderSyntaxValid;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("refresh", "   ")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("missing delta-seconds"));
        Ok(())
    }

    #[test]
    fn trailing_semicolon_is_accepted() -> anyhow::Result<()> {
        // Trailing semicolon should be ignored (no parameter present)
        let rule = MessageRefreshHeaderSyntaxValid;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("refresh", "5;")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn url_with_comma_is_reported() -> anyhow::Result<()> {
        // Because the rule treats commas as list separators, a URL containing a comma is flagged
        let rule = MessageRefreshHeaderSyntaxValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("refresh", "5; url=/a,b")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn url_whitespace_percent_encoding_and_scheme_are_reported() -> anyhow::Result<()> {
        // whitespace in url
        let rule = MessageRefreshHeaderSyntaxValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("refresh", "5; url=/in valid")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("contains whitespace"));

        // invalid percent-encoding
        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("refresh", "5; url=/x%G1")],
        );
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());
        let msg2 = v2.unwrap().message;
        assert!(msg2.contains("percent-encoding"));

        // invalid scheme (starts with digit)
        let tx3 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("refresh", "5; url=1http://example/")],
        );
        let v3 = rule.check_transaction(&tx3, None, &crate::test_helpers::make_test_rule_config());
        assert!(v3.is_some());
        let msg3 = v3.unwrap().message;
        assert!(msg3.contains("invalid scheme"));

        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageRefreshHeaderSyntaxValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageRefreshHeaderSyntaxValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_refresh_header_syntax_valid".into(),
            toml::Value::Table(table),
        );

        let _ = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
