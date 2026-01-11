// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Vary` header value must be either `*` or a comma-separated list of header field-names.
/// Field-names must conform to the `token` grammar (tchar); `*` must not be combined with other values.
pub struct ServerVaryHeaderValid;

impl Rule for ServerVaryHeaderValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_vary_header_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
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

        // Track whether '*' appears and count effective tokens across all header fields
        let mut saw_star = false;
        let mut total_tokens = 0usize;

        for hv in resp.headers.get_all("vary").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Vary header contains non-UTF8 value".into(),
                    })
                }
            };

            // Detect empty/empty-after-trim tokens such as trailing commas or consecutive commas
            for raw in s.split(',') {
                if raw.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Vary header contains empty token (e.g., trailing or consecutive commas)".into(),
                    });
                }
            }

            for token in crate::helpers::headers::parse_list_header(s) {
                total_tokens += 1;

                if token == "*" {
                    saw_star = true;
                    continue;
                }

                // Validate token characters for header field-name
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Vary header contains invalid field-name token character: '{}'",
                            c
                        ),
                    });
                }
            }
        }

        // Empty Vary header (present but no effective tokens) is invalid
        if total_tokens == 0 && resp.headers.get_all("vary").iter().next().is_some() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Vary header is present but empty".into(),
            });
        }

        if saw_star && total_tokens > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Vary header: '*' must not be combined with other field-names".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(None, false)]
    #[case(Some("*"), false)]
    #[case(Some("accept-encoding"), false)]
    #[case(Some("Accept-Encoding, User-Agent"), false)]
    #[case(Some("accept-encoding, *"), true)]
    #[case(Some("*, accept-encoding"), true)]
    #[case(Some(""), true)]
    #[case(Some("x@bad"), true)]
    #[case(Some("Accept-Encoding,"), true)]
    #[case(Some(",Accept-Encoding"), true)]
    #[case(Some("Accept-Encoding,,User-Agent"), true)]
    #[case(Some("   "), true)]
    #[case(Some(","), true)]
    #[case(Some("\"Accept-Encoding\""), true)]
    fn vary_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerVaryHeaderValid;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("vary", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_merged() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerVaryHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("vary", HeaderValue::from_static("Accept-Encoding"));
        hm.append("vary", HeaderValue::from_static("User-Agent"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn star_combined_across_header_fields_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerVaryHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("vary", HeaderValue::from_static("*"));
        hm.append("vary", HeaderValue::from_static("Accept-Encoding"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerVaryHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("vary", bad);
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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_vary_header_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerVaryHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn no_response_returns_none() {
        let rule = ServerVaryHeaderValid;
        let tx = crate::test_helpers::make_test_transaction(); // request-only, no response
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }
}
