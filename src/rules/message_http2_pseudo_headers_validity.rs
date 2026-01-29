// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHttp2PseudoHeadersValidity;

impl Rule for MessageHttp2PseudoHeadersValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_http2_pseudo_headers_validity"
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
        // Validate request-related pseudo-header semantics using canonical transaction fields.
        // Many capture formats do not retain raw HTTP/2 pseudo-header names in the HeaderMap (they are
        // represented as `RequestInfo.method` and `RequestInfo.uri` in the canonical transaction). Validate
        // those canonical fields conservatively to detect malformed pseudo-header-like values.

        // Validate :method -> RequestInfo.method
        let method = tx.request.method.trim();
        if let Some(c) = crate::helpers::token::find_invalid_token_char(method) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Invalid token '{}' in :method (request method)", c),
            });
        }

        // CONNECT special-case: request-target must be authority-form (no path)
        let method_is_connect = method.eq_ignore_ascii_case("CONNECT");

        // Use helpers::uri to decide whether request URI contains a path
        let path_opt = crate::helpers::uri::extract_path_from_request_target(&tx.request.uri);

        if method_is_connect {
            // CONNECT must not have a path, and the request-target should be authority-form
            if path_opt.is_some() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/2 CONNECT-like request must not include a path in the request-target"
                            .into(),
                });
            }
            // Validate authority-like form (host[:port]) similar to Host header rules
            let auth = tx.request.uri.trim();
            if auth.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "CONNECT request-target (authority) is empty".into(),
                });
            }
            if auth.contains('@') {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "CONNECT request-target must not include userinfo".into(),
                });
            }
            if auth.starts_with('[') {
                if crate::helpers::ipv6::parse_bracketed_ipv6(auth).is_none() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CONNECT request-target contains malformed bracketed IPv6".into(),
                    });
                }
            } else {
                // If there are multiple ':' characters this is likely an unbracketed IPv6
                // literal (with or without a trailing port). Reject it — IPv6 literals
                // in authority must be bracketed.
                let colon_count = auth.chars().filter(|&c| c == ':').count();
                if colon_count > 1 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CONNECT request-target IPv6 literal must be bracketed".into(),
                    });
                }

                // Single colon -> host:port, validate port
                if auth.contains(':') {
                    if let Some(idx) = auth.rfind(':') {
                        let port = &auth[idx + 1..];
                        if port.is_empty() || !port.chars().all(|c: char| c.is_ascii_digit()) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "CONNECT request-target port invalid".into(),
                            });
                        }
                        if let Ok(n) = port.parse::<u32>() {
                            if n == 0 || n > 65535 {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "CONNECT request-target port out of range".into(),
                                });
                            }
                        }
                    }
                }
            }
        } else {
            // Non-CONNECT: accept asterisk-form for OPTIONS, otherwise require a path component
            let s_trim = tx.request.uri.trim();
            if s_trim == "*" {
                if !method.eq_ignore_ascii_case("OPTIONS") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Asterisk ('*') request-target is only permitted with OPTIONS method"
                                .into(),
                    });
                }
            } else if path_opt.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "HTTP/2 request missing ':path' pseudo-header equivalent (no path in request-target)".into(),
                });
            }
            // Validate path for whitespace and percent-encoding correctness
            if let Some(p) = path_opt {
                if crate::helpers::uri::contains_whitespace(&p) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "':path' equivalent in request-target contains whitespace".into(),
                    });
                }
                if let Some(msg) = crate::helpers::uri::check_percent_encoding(&p) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid percent-encoding in request-target path: {}",
                            msg
                        ),
                    });
                }
            }
        }

        // If request URI appears to be absolute (contains '://'), validate scheme and authority.
        // We run scheme validation even if `extract_origin_if_absolute` returns `None` (which happens
        // for invalid schemes or missing authority) so we can surface helpful violations.
        if tx.request.uri.contains("://") {
            // Validate scheme even for invalid origins like "1http://..."
            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(&tx.request.uri) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid scheme in request-target: {}", msg),
                });
            }
            // If origin can be cleanly extracted, reuse origin-based checks.
            if let Some(origin) = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri) {
                if let Some(colon_idx) = origin.find("://") {
                    let authority = &origin[colon_idx + 3..];
                    if authority.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Absolute request-target missing authority".into(),
                        });
                    }
                    if authority.contains('@') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Request-target authority must not include userinfo".into(),
                        });
                    }
                    if authority.starts_with('[')
                        && crate::helpers::ipv6::parse_bracketed_ipv6(authority).is_none()
                    {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Request-target authority contains malformed bracketed IPv6"
                                .into(),
                        });
                    }
                }
            } else {
                // `extract_origin_if_absolute` failed (likely missing authority or whitespace in origin).
                // If it contains '://', but couldn't extract origin, it's an absolute-form with issues.
                // Check for missing authority explicitly.
                if let Some(idx) = tx.request.uri.find("://") {
                    let after = &tx.request.uri[idx + 3..];
                    if after.is_empty() || after.starts_with('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Absolute request-target missing authority".into(),
                        });
                    }
                }
            }
        }

        // Validate response pseudo-header semantics using canonical response fields.
        if let Some(resp) = &tx.response {
            // Ensure status in range 100..=599 (valid HTTP status codes are 100-599)
            if !(100..=599).contains(&resp.status) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "':status' equivalent in response must be a valid 3-digit status code"
                        .into(),
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
    #[case("GET", "/", false, None)]
    #[case("GET", "", true, Some("missing ':path'"))]
    #[case("CONNECT", "example.com:443", false, None)]
    #[case("CONNECT", "/", true, Some("must not include a path"))]
    #[case("GE T", "/", true, Some("Invalid token"))]
    fn request_pseudo_cases(
        #[case] method: &str,
        #[case] uri: &str,
        #[case] expect_violation: bool,
        #[case] expected_contains: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.uri = uri.to_string();
        let rule = MessageHttp2PseudoHeadersValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
            if let Some(sub) = expected_contains {
                assert!(v.unwrap().message.contains(sub));
            }
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(200, false, None)]
    #[case(0, true, Some("3-digit"))]
    fn response_pseudo_cases(
        #[case] status: u16,
        #[case] expect_violation: bool,
        #[case] expected_contains: Option<&str>,
    ) -> anyhow::Result<()> {
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let rule = MessageHttp2PseudoHeadersValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
            if let Some(sub) = expected_contains {
                assert!(v.unwrap().message.contains(sub));
            }
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageHttp2PseudoHeadersValidity;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_http2_pseudo_headers_validity".into(),
            toml::Value::Table(table),
        );
        let _ = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn request_absolute_scheme_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "1http://example.com/".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid scheme"));
    }

    #[test]
    fn request_path_percent_encoding_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/bad%2G".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn request_path_whitespace_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/foo bar".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("contains whitespace"));
    }

    #[test]
    fn connect_empty_authority_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("CONNECT request-target (authority) is empty"));
    }

    #[test]
    fn connect_malformed_ipv6_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("malformed bracketed IPv6"));
    }

    #[test]
    fn connect_port_invalid_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:abc".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port invalid"));
    }

    #[test]
    fn connect_port_out_of_range_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:70000".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port out of range"));
    }

    #[test]
    fn connect_empty_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port invalid"));
    }

    #[test]
    fn connect_userinfo_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "user:pass@example.com".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not include userinfo"));
    }

    #[test]
    fn connect_bracketed_ipv6_with_port_valid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1]:443".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_unbracketed_ipv6_without_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "::1".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must be bracketed"));
    }

    #[test]
    fn connect_unbracketed_ipv6_with_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "fe80::1:80".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must be bracketed"));
    }

    #[test]
    fn request_absolute_origin_valid_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_path_percent_encoding_valid_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/ok%20here".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn method_token_non_ascii_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GE€T".into();
        tx.request.uri = "/".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid token"));
    }

    #[test]
    fn response_status_low_out_of_range_is_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(99, &[]);
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("3-digit"));
    }

    #[test]
    fn absolute_missing_authority_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https:///path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Absolute request-target missing authority"));
    }

    #[test]
    fn absolute_authority_userinfo_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "http://user:pass@example.com/path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not include userinfo"));
    }

    #[test]
    fn asterisk_form_options_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_form_non_options_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "*".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk ('*')"));
    }

    #[test]
    fn response_status_out_of_range_is_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(700, &[]);
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            None,
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("3-digit"));
    }
}
