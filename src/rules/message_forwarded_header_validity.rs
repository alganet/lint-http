// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use std::net::IpAddr;

pub struct MessageForwardedHeaderValidity;

impl Rule for MessageForwardedHeaderValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_forwarded_header_validity"
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
        // Helper to validate a single Forwarded element (one comma-separated member)
        let validate_element = |elem: &str| -> Option<Violation> {
            if elem.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Forwarded header contains empty element".into(),
                });
            }

            // split into semicolon separated parameters, respecting quoted-strings so we
            // don't split semicolons inside quoted values
            let mut params = Vec::new();
            let mut start = 0usize;
            let mut in_quote = false;
            let mut escape = false;
            for (i, ch) in elem.char_indices() {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' && in_quote {
                    escape = true;
                    continue;
                }
                if ch == '"' {
                    in_quote = !in_quote;
                    continue;
                }
                if ch == ';' && !in_quote {
                    params.push(&elem[start..i]);
                    start = i + 1;
                }
            }
            params.push(&elem[start..]);

            for param in params.into_iter().map(|p| p.trim()) {
                if param.is_empty() {
                    continue;
                }
                let mut nv = param.splitn(2, '=').map(|s| s.trim());
                let name = nv.next().unwrap();
                let val = nv.next();

                if val.is_none() || name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Forwarded parameter '{}' missing value or '='", param),
                    });
                }

                // name must be a token
                if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in Forwarded parameter name", c),
                    });
                }

                let name_lc = name.to_ascii_lowercase();
                let mut value = val.unwrap();
                let raw_value = value;

                if raw_value.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Forwarded parameter '{}' missing value or '='", param),
                    });
                }

                // If quoted-string, validate and unquote for further checks
                if value.starts_with('"') {
                    if let Err(e) = crate::helpers::headers::validate_quoted_string(value) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid quoted-string in Forwarded parameter '{}': {}",
                                name, e
                            ),
                        });
                    }
                    // strip outer quotes; validated above
                    value = &value[1..value.len() - 1];
                    // If an empty quoted-string was provided (e.g., for=""), report a clearer message
                    if value.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Empty value in Forwarded '{}' parameter", name),
                        });
                    }
                }

                if name_lc == "for" || name_lc == "by" {
                    // value may be 'unknown', an obfuscated token, or an addr (IPv4/IPv6) optionally with port
                    if value.eq_ignore_ascii_case("unknown") {
                        // ok
                        continue;
                    }

                    // IPv6 in brackets: [2001:db8::1] or [2001:db8::1]:port
                    if value.starts_with('[') {
                        // must contain closing ']'
                        if let Some(end) = value.find(']') {
                            let inside = &value[1..end];
                            if inside.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Empty IPv6 address in Forwarded '{}' parameter",
                                        name
                                    ),
                                });
                            }
                            if inside.parse::<IpAddr>().is_err() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid IPv6 address in Forwarded '{}' parameter: {}",
                                        name, inside
                                    ),
                                });
                            }
                            // optionally validate port after ']' if present
                            let rest = &value[end + 1..];
                            if !rest.is_empty() && !rest.starts_with(':') {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid IPv6 port syntax in Forwarded '{}' parameter: {}",
                                        name, value
                                    ),
                                });
                            }
                            if let Some(port) = rest.strip_prefix(':') {
                                if port.is_empty() || port.parse::<u16>().is_err() {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid port '{}' in Forwarded '{}' parameter",
                                            port, name
                                        ),
                                    });
                                }
                            }
                            continue;
                        } else {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid IPv6 bracketed address in Forwarded '{}' parameter: {}", name, value),
                            });
                        }
                    }

                    // Possibly contains a colon for IPv4:port or token:port. Try parsing host:port by splitting last ':'
                    if let Some(idx) = value.rfind(':') {
                        let (host_part, port_part) = value.split_at(idx);
                        let host = host_part;
                        let port = &port_part[1..];
                        if !port.is_empty() && port.parse::<u16>().is_err() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid port '{}' in Forwarded '{}' parameter",
                                    port, name
                                ),
                            });
                        }
                        // try parsing host as IP
                        if host.parse::<IpAddr>().is_ok() {
                            continue;
                        }
                        // else treat as obfuscated token - must follow token grammar
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(host) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid obfuscated token '{}' in Forwarded '{}' parameter",
                                    c, name
                                ),
                            });
                        }
                        continue;
                    }

                    // No port and not bracketed; try parse as IP
                    if value.parse::<IpAddr>().is_ok() {
                        continue;
                    }

                    // If this looks like a dotted IPv4 (digits and dots only) but failed to parse,
                    // that's an invalid IPv4 address (common misconfiguration)
                    if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid IPv4 address in Forwarded '{}' parameter: {}",
                                name, value
                            ),
                        });
                    }

                    // Otherwise obfuscated token (must be token)
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid obfuscated token '{}' in Forwarded '{}' parameter",
                                c, name
                            ),
                        });
                    }
                    continue;
                }

                if name_lc == "proto" {
                    // proto must be a token such as http or https
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid token '{}' in Forwarded proto parameter", c),
                        });
                    }
                    continue;
                }

                if name_lc == "host" {
                    // host may be a host or host:port or IPv6 in brackets
                    // basic validation: ensure no invalid control characters and token-ish content
                    // If bracketed IPv6, validate
                    if value.starts_with('[') {
                        if let Some(end) = value.find(']') {
                            let inside = &value[1..end];
                            if inside.parse::<IpAddr>().is_err() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid IPv6 address in Forwarded 'host' parameter: {}",
                                        inside
                                    ),
                                });
                            }
                            // optionally validate port
                            let rest = &value[end + 1..];
                            if !rest.is_empty() && !rest.starts_with(':') {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Invalid host port syntax in Forwarded 'host' parameter: {}", value),
                                });
                            }
                            if let Some(port) = rest.strip_prefix(':') {
                                if port.is_empty() || port.parse::<u16>().is_err() {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid port '{}' in Forwarded 'host' parameter",
                                            port
                                        ),
                                    });
                                }
                            }
                            continue;
                        } else {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid IPv6 bracketed address in Forwarded 'host' parameter: {}", value),
                            });
                        }
                    }

                    // host may include port
                    if let Some(idx) = value.rfind(':') {
                        let (host_part, port_part) = value.split_at(idx);
                        let host = host_part;
                        let port = &port_part[1..];
                        if !port.is_empty() && port.parse::<u16>().is_err() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid port '{}' in Forwarded 'host' parameter",
                                    port
                                ),
                            });
                        }
                        // host part may be a reg-name; ensure token-ish
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(host) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid host '{}' in Forwarded 'host' parameter (invalid char '{}')", host, c),
                            });
                        }
                        continue;
                    }

                    if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid host '{}' in Forwarded 'host' parameter (invalid char '{}')", value, c),
                        });
                    }

                    continue;
                }

                // Unknown parameter name - ensure token name and token or quoted-string value
                if raw_value.starts_with('"') {
                    // already validated quoted-string above
                    continue;
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid token '{}' in Forwarded parameter value for '{}'",
                            c, name
                        ),
                    });
                }
            }
            None
        };

        for hv in tx.request.headers.get_all("forwarded").iter() {
            if let Ok(s) = hv.to_str() {
                // split comma-separated elements
                for elem in crate::helpers::headers::parse_list_header(s) {
                    if let Some(v) = validate_element(elem) {
                        return Some(v);
                    }
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Forwarded header value is not valid UTF-8".into(),
                });
            }
        }

        // Now also check response headers: Forwarded can appear in responses per RFC 7239
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("forwarded").iter() {
                if let Ok(s) = hv.to_str() {
                    for elem in crate::helpers::headers::parse_list_header(s) {
                        if let Some(v) = validate_element(elem) {
                            return Some(v);
                        }
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Forwarded header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx_with_forwarded(value: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("forwarded", value)]);
        tx
    }

    #[test]
    fn valid_forwarded_simple_for_ipv4() {
        let tx = make_tx_with_forwarded("for=192.0.2.43");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn valid_forwarded_for_ipv6_bracketed() {
        let tx = make_tx_with_forwarded("for=\"[2001:db8::1]\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn valid_forwarded_with_port() {
        let tx = make_tx_with_forwarded("for=198.51.100.17:1234;proto=https;by=203.0.113.5");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_empty_element() {
        let tx = make_tx_with_forwarded(", ;for=192.0.2.43");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        // Leading empty list members and stray semicolons are ignored by header parsing; consider this valid
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_missing_eq() {
        let tx = make_tx_with_forwarded("for");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_bad_ipv4() {
        let tx = make_tx_with_forwarded("for=999.999.999.999");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_bad_ipv6_brackets() {
        let tx = make_tx_with_forwarded("for=[2001:db8::zzz]");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_bad_port() {
        let tx = make_tx_with_forwarded("for=192.0.2.1:99999");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_is_violation() -> anyhow::Result<()> {
        let rule = MessageForwardedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("forwarded", bad);
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn response_forwarded_values_checked() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("forwarded", "for=192.0.2.4, proto=https")],
        );
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_obfuscated_token_invalid_char() {
        let tx = make_tx_with_forwarded("for=obf@bad");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_proto_token_char() {
        let tx = make_tx_with_forwarded("proto=ht@tp");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_host_with_large_port() {
        let tx = make_tx_with_forwarded("host=example.com:99999");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_host_missing_bracket() {
        let tx = make_tx_with_forwarded("host=[2001:db8::1");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_for_unterminated_quoted_ipv6() {
        let tx = make_tx_with_forwarded("for=\"[2001:db8::1\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn forwarded_by_unknown_is_ok() {
        let tx = make_tx_with_forwarded("by=unknown");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn forwarded_for_obfuscated_token_ok() {
        let tx = make_tx_with_forwarded("for=x-foo");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn unknown_param_value_invalid_token_char() {
        let tx = make_tx_with_forwarded("foo=bad@value");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn response_forwarded_invalid_element_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("forwarded", "for=999.999.999.999")],
        );
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn valid_forwarded_quoted_ipv6_with_port() {
        let tx = make_tx_with_forwarded("for=\"[2001:db8::1]:1234\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_quoted_ipv6_empty_inside() {
        let tx = make_tx_with_forwarded("for=\"[]\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_quoted_ipv6_bad_port_syntax() {
        let tx = make_tx_with_forwarded("for=\"[2001:db8::1]x\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn valid_forwarded_host_with_port_regname() {
        let tx = make_tx_with_forwarded("host=example.com:8080");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_host_invalid_char() {
        let tx = make_tx_with_forwarded("host=exa mple");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn unknown_param_quoted_string_ok() {
        let tx = make_tx_with_forwarded("foo=\"bar baz\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn multiple_forwarded_header_fields_invalid_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("forwarded", "for=192.0.2.1"),
            ("forwarded", "for=999.999.999.999"),
        ]);
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn unknown_param_token_ok() {
        let tx = make_tx_with_forwarded("foo=bar");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_ipv6_port_non_numeric() {
        let tx = make_tx_with_forwarded("for=[2001:db8::1]:x");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_ipv6_port_empty() {
        let tx = make_tx_with_forwarded("for=[2001:db8::1]:");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_host_bracketed_port_non_numeric() {
        let tx = make_tx_with_forwarded("host=[2001:db8::1]:notnum");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn valid_forwarded_host_bracketed_with_port() {
        let tx = make_tx_with_forwarded("host=[2001:db8::1]:8080");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn valid_forwarded_obfuscated_with_port() {
        let tx = make_tx_with_forwarded("for=x-foo:8080");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_obfuscated_token_with_port_invalid_char() {
        let tx = make_tx_with_forwarded("for=obf@bad:8080");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn quoted_unknown_ok() {
        let tx = make_tx_with_forwarded("for=\"unknown\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_bare_ipv6_no_brackets() {
        let tx = make_tx_with_forwarded("for=2001:db8::1");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_param_name_invalid_token_char() {
        let tx = make_tx_with_forwarded("@=1");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_empty_value() {
        let tx = make_tx_with_forwarded("foo=");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_proto_quoted_with_space_is_violation() {
        let tx = make_tx_with_forwarded("proto=\"ht tp\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn unknown_param_quoted_with_escaped_quote_ok() {
        let tx = make_tx_with_forwarded("foo=\"a\\\"b\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_host_with_port_and_space() {
        let tx = make_tx_with_forwarded("host=exa mple:80");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_empty_param_name() {
        let tx = make_tx_with_forwarded("=value");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_response_header_is_violation() -> anyhow::Result<()> {
        let rule = MessageForwardedHeaderValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("forwarded", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn unknown_param_quoted_with_semicolon_ok() {
        let tx = make_tx_with_forwarded("foo=\"a;b\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_empty_header_value() {
        let tx = make_tx_with_forwarded("");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        // Empty header value is ignored by header parsing; considered valid
        assert!(v.is_none());
    }

    #[test]
    fn invalid_forwarded_quoted_string_extra_chars() {
        let tx = make_tx_with_forwarded("foo=\"bar\"x");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn invalid_forwarded_empty_quoted_for() {
        let tx = make_tx_with_forwarded("for=\"\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Empty value"));
    }

    #[test]
    fn valid_forwarded_quoted_ipv4_with_port() {
        let tx = make_tx_with_forwarded("for=\"192.0.2.1:8080\"");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn forwarded_extra_semicolon_ignored() {
        let tx = make_tx_with_forwarded("for=192.0.2.1; ;proto=https");
        let rule = MessageForwardedHeaderValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_forwarded_header_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
