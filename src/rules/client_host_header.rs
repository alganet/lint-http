// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use std::net::IpAddr;

pub struct ClientHostHeader;

impl Rule for ClientHostHeader {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_host_header"
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
        let host_values = tx.request.headers.get_all("host");
        let host_count = host_values.iter().count();
        if host_count == 0 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing Host header".into(),
            });
        }
        if host_count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Host header fields present".into(),
            });
        }

        let s = match crate::helpers::headers::get_header_str(&tx.request.headers, "host") {
            Some(s) => s.trim(),
            None => {
                // We checked count >= 1 above, so it must be non-UTF8
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Host header is not valid UTF-8".into(),
                });
            }
        };

        // Empty Host value is not allowed per RFC 9112
        if s.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Host header is empty".into(),
            });
        }

        // Host header MUST NOT include userinfo (user:pass@). Detect this first.
        if s.contains('@') {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Host header MUST NOT include userinfo (user:pass@)".into(),
            });
        }

        // Bracketed IPv6 literal: [::1]:port or [::1]
        if s.starts_with('[') {
            match crate::helpers::ipv6::parse_bracketed_ipv6(s) {
                Some((_inner, port_opt)) => {
                    if let Some(port) = port_opt {
                        return self.validate_port(port, config);
                    }
                    return None;
                }
                None => {
                    // malformed bracketed host — flag as violation
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Malformed bracketed IPv6 literal in Host header".into(),
                    });
                }
            }
        }

        // Non-bracketed form. If it contains multiple ':' it may be an unbracketed IPv6 address.
        let colon_count = s.chars().filter(|&c| c == ':').count();
        if colon_count == 0 {
            return None;
        }

        if colon_count > 1 {
            if crate::helpers::ipv6::looks_like_unbracketed_ipv6_with_port(s) {
                if let Some(idx) = s.rfind(':') {
                    let (maybe_host, port_part) = s.split_at(idx);
                    let port = &port_part[1..];
                    if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                        if let Ok(ip) = maybe_host.parse::<IpAddr>() {
                            if matches!(ip, IpAddr::V6(_)) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message:
                                        "IPv6 literal with port must be bracketed in Host header"
                                            .into(),
                                });
                            }
                        }
                    }
                }
            }
            return None;
        }

        // Single colon — interpret as host:port and validate the port
        if let Some(idx) = s.rfind(':') {
            let port = &s[idx + 1..];
            return self.validate_port(port, config);
        }

        None
    }
}

impl ClientHostHeader {
    fn validate_port(
        &self,
        port: &str,
        rule_config: &crate::rules::RuleConfig,
    ) -> Option<Violation> {
        if port.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: rule_config.severity,
                message: "Host header includes empty port".into(),
            });
        }
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return Some(Violation {
                rule: self.id().into(),
                severity: rule_config.severity,
                message: format!("Host header port is not numeric: '{}'", port),
            });
        }
        if let Ok(n) = port.parse::<u32>() {
            if n == 0 || n > 65535 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: rule_config.severity,
                    message: format!("Host header port out of range: {}", n),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: rule_config.severity,
                message: format!("Host header port is invalid: '{}'", port),
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
    #[case(vec![], true, Some("Request missing Host header"))]
    #[case(vec![("host", "example.com")], false, None)]
    #[case(vec![("host", "example.com:80")], false, None)]
    #[case(vec![("host", "   ")], true, Some("Host header is empty"))]
    #[case(vec![("host", "  example.com  ")], false, None)]
    #[case(vec![("host", "")], true, Some("Host header is empty"))]
    #[case(vec![("host", "example.com:0")], true, None)]
    #[case(vec![("host", "example.com:65536")], true, None)]
    #[case(vec![("host", "example.com:abc")], true, None)]
    #[case(vec![("host", "example.com:")], true, None)]
    #[case(vec![("host", "[::1]:443")], false, None)]
    #[case(vec![("host", "[::1]")], false, None)]
    #[case(vec![("host", "[::1]:-1")], true, None)]
    #[case(vec![("host", "fe80::1")], false, None)]
    #[case(vec![("host", "fe80::1:80")], true, None)]
    #[case(vec![("host", "fe80::abcd:8080")], true, None)]
    #[case(vec![("host", "1.2.3.4:80")], false, None)]
    #[case(vec![("host", "fe80::1:")], false, None)]
    #[case(vec![("host", "user:pass@example.com")], true, None)]
    #[case(vec![("host", "user@example.com:80")], true, None)]
    #[case(vec![("host", "user:pass@[::1]:80")], true, None)]
    #[case(vec![("host", "[::1")], true, Some("Malformed bracketed IPv6 literal in Host header"))]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ClientHostHeader;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&header_pairs);
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(violation.is_some());
            if let Some(m) = expected_message {
                assert_eq!(violation.map(|v| v.message), Some(m.to_string()));
            }
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn multiple_host_headers_produced_violation() -> anyhow::Result<()> {
        let rule = ClientHostHeader;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("host", "example.com"),
            ("host", "other.example.com"),
        ]);
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Multiple Host header fields present".to_string())
        );
        Ok(())
    }

    #[test]
    fn host_header_non_utf8_returns_violation() -> anyhow::Result<()> {
        let rule = ClientHostHeader;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = make_test_transaction();
        let mut hm = HeaderMap::new();
        // Insert an invalid UTF-8 header value
        hm.insert("host", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Host header is not valid UTF-8".to_string())
        );
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let r = ClientHostHeader;
        assert_eq!(
            crate::rules::Rule::scope(&r),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn port_parse_error_returns_invalid_message() -> anyhow::Result<()> {
        let rule = ClientHostHeader;
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "host",
            "example.com:999999999999999999999",
        )]);

        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert!(v.message.starts_with("Host header port is invalid"));
        Ok(())
    }

    #[test]
    fn validate_port_empty_returns_violation() -> anyhow::Result<()> {
        let rule = ClientHostHeader;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.validate_port("", &cfg);
        assert!(v.is_some());
        assert_eq!(
            v.map(|v| v.message),
            Some("Host header includes empty port".to_string())
        );
        Ok(())
    }
}
