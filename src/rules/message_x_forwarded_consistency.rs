// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageXForwardedConsistency;

impl Rule for MessageXForwardedConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_x_forwarded_consistency"
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
        use crate::helpers::headers::parse_list_header;

        let check_xff = |val: &str| -> Option<Violation> {
            for token in parse_list_header(val) {
                let t = token;
                if t.eq_ignore_ascii_case("unknown") {
                    continue;
                }
                // Accept IP addresses (v4 or v6)
                if t.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid X-Forwarded-For member: '{}'", t),
                });
            }
            None
        };

        let check_xfp = |val: &str| -> Option<Violation> {
            for token in parse_list_header(val) {
                let t = token;
                // Common schemes are http/https; be conservative and accept those only
                if t.eq_ignore_ascii_case("http") || t.eq_ignore_ascii_case("https") {
                    continue;
                }
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid X-Forwarded-Proto value: '{}'", t),
                });
            }
            None
        };

        let check_xfh = |val: &str| -> Option<Violation> {
            for token in parse_list_header(val) {
                let t = token;

                // Host may be "host" or "host:port" or bracketed IPv6 "[::1]" or "[::1]:8080"
                // Check bracketed IPv6 first
                if t.starts_with('[') {
                    if let Some((ip_body, port_opt)) = crate::helpers::ipv6::parse_bracketed_ipv6(t)
                    {
                        if ip_body.parse::<std::net::Ipv6Addr>().is_err() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid IPv6 literal in X-Forwarded-Host: '{}'",
                                    t
                                ),
                            });
                        }
                        if let Some(port) = port_opt {
                            if crate::helpers::ipv6::parse_port_str(port).is_none() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Invalid port in X-Forwarded-Host: '{}'", t),
                                });
                            }
                        }
                        continue;
                    } else {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Malformed bracketed IPv6 in X-Forwarded-Host: '{}'",
                                t
                            ),
                        });
                    }
                }

                // Otherwise split host:port if present
                if let Some(pos) = t.rfind(':') {
                    let host = &t[..pos];
                    let port = &t[pos + 1..];
                    if host.is_empty() || port.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid X-Forwarded-Host component: '{}'", t),
                        });
                    }
                    if crate::helpers::ipv6::parse_port_str(port).is_none() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid port in X-Forwarded-Host: '{}'", t),
                        });
                    }
                    // Validate host part is not empty and not containing whitespace or '@'
                    if host.contains('/')
                        || host.contains('@')
                        || host.contains(' ')
                        || host.contains('\t')
                    {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid host in X-Forwarded-Host: '{}'", t),
                        });
                    }
                    continue;
                }

                // No port: ensure simple host is ok (no whitespace or '@')
                if t.is_empty()
                    || t.contains('/')
                    || t.contains('@')
                    || t.contains(' ')
                    || t.contains('\t')
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid host in X-Forwarded-Host: '{}'", t),
                    });
                }
            }
            None
        };

        // Check request headers
        if let Some(v) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "x-forwarded-for")
        {
            if let Some(vi) = check_xff(v) {
                return Some(vi);
            }
        }
        if let Some(v) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "x-forwarded-proto")
        {
            if let Some(vi) = check_xfp(v) {
                return Some(vi);
            }
        }
        if let Some(v) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "x-forwarded-host")
        {
            if let Some(vi) = check_xfh(v) {
                return Some(vi);
            }
        }

        // Check response headers too (some proxies echo these)
        if let Some(resp) = &tx.response {
            if let Some(v) =
                crate::helpers::headers::get_header_str(&resp.headers, "x-forwarded-for")
            {
                if let Some(vi) = check_xff(v) {
                    return Some(vi);
                }
            }
            if let Some(v) =
                crate::helpers::headers::get_header_str(&resp.headers, "x-forwarded-proto")
            {
                if let Some(vi) = check_xfp(v) {
                    return Some(vi);
                }
            }
            if let Some(v) =
                crate::helpers::headers::get_header_str(&resp.headers, "x-forwarded-host")
            {
                if let Some(vi) = check_xfh(v) {
                    return Some(vi);
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

    #[rstest]
    #[case(Some("203.0.113.195"), false)]
    #[case(Some("203.0.113.195, 198.51.100.17"), false)]
    #[case(Some("2001:db8::1"), false)]
    #[case(Some("unknown"), false)]
    #[case(Some("not-an-ip"), true)]
    #[case(None, false)]
    fn check_xff_cases(
        #[case] val: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = val {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-for", v)]);
        }
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn response_headers_are_checked() {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-for", "not-an-ip")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());

        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-forwarded-proto", "https")],
        );
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_none());
    }

    #[rstest]
    #[case(Some("https"), false)]
    #[case(Some("http"), false)]
    #[case(Some("HTTPS"), false)]
    #[case(Some("ftp"), true)]
    #[case(None, false)]
    fn check_xfp_cases(
        #[case] val: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = val {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-proto", v)]);
        }
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("example.com"), false)]
    #[case(Some("example.com:8080"), false)]
    #[case(Some("[::1]:8080"), false)]
    #[case(Some("user@host"), true)]
    #[case(Some("[::1"), true)]
    #[case(None, false)]
    fn check_xfh_cases(
        #[case] val: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = val {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-host", v)]);
        }
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        use hyper::header::HeaderValue;
        let rule = MessageXForwardedConsistency;

        // Non-UTF8 header should be ignored (get_header_str returns None)
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = tx.request.headers.clone();
        hm.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());

        // Also for response
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm2 = tx2.response.as_ref().unwrap().headers.clone();
        hm2.append(
            "x-forwarded-proto",
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx2.response.as_mut().unwrap().headers = hm2;
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_none());
    }

    #[test]
    fn check_xfp_multiple_values_mixed() {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-proto", "https, ftp")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid X-Forwarded-Proto"));
    }

    #[test]
    fn xff_wildcard_is_invalid() {
        let rule = MessageXForwardedConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-forwarded-for", "*")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageXForwardedConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_x_forwarded_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
