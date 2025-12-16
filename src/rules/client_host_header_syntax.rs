// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;
use std::net::IpAddr;

pub struct ClientHostHeaderSyntax;

impl Rule for ClientHostHeaderSyntax {
    fn id(&self) -> &'static str {
        "client_host_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        _tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let hv = _tx.request.headers.get("host")?;
        let s = match hv.to_str() {
            Ok(s) => s.trim(),
            Err(_) => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: "Host header is not valid UTF-8".into(),
                });
            }
        };

        // Host header MUST NOT include userinfo (user:pass@). Detect this first.
        if s.contains('@') {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Host header MUST NOT include userinfo (user:pass@)".into(),
            });
        }

        // Bracketed IPv6 literal: [::1]:port or [::1]
        if let Some(rest) = s.strip_prefix('[') {
            if let Some(end_idx) = rest.find(']') {
                let after = &rest[end_idx + 1..];
                if let Some(port) = after.strip_prefix(':') {
                    return self.validate_port(port, _config);
                }
                return None;
            }
            // malformed bracketed host; let other rules handle it
            return None;
        }

        // Non-bracketed form. If it contains multiple ':' it may be an unbracketed IPv6 address.
        // Detect the pattern where an unbracketed IPv6 literal is followed by :<digits> indicating
        // a port (e.g., `fe80::1:80`) — that's a violation because IPv6+port must be bracketed.
        let colon_count = s.chars().filter(|&c| c == ':').count();
        if colon_count == 0 {
            return None;
        }

        if colon_count > 1 {
            if let Some(idx) = s.rfind(':') {
                let (maybe_host, port_part) = s.split_at(idx);
                let port = &port_part[1..];
                if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(ip) = maybe_host.parse::<IpAddr>() {
                        if matches!(ip, IpAddr::V6(_)) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: crate::rules::get_rule_severity(_config, self.id()),
                                message: "IPv6 literal with port must be bracketed in Host header"
                                    .into(),
                            });
                        }
                    }
                }
            }
            return None;
        }

        // Single colon — interpret as host:port and validate the port
        if let Some(idx) = s.rfind(':') {
            let port = &s[idx + 1..];
            return self.validate_port(port, _config);
        }

        None
    }
}

impl ClientHostHeaderSyntax {
    fn validate_port(&self, port: &str, cfg: &crate::config::Config) -> Option<Violation> {
        if port.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(cfg, self.id()),
                message: "Host header includes empty port".into(),
            });
        }
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(cfg, self.id()),
                message: format!("Host header port is not numeric: '{}'", port),
            });
        }
        if let Ok(n) = port.parse::<u32>() {
            if n == 0 || n > 65535 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(cfg, self.id()),
                    message: format!("Host header port out of range: {}", n),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(cfg, self.id()),
                message: format!("Host header port is invalid: '{}'", port),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case(vec![], false)]
    #[case(vec![("host", "example.com")], false)]
    #[case(vec![("host", "example.com:80")], false)]
    #[case(vec![("host", "example.com:0")], true)]
    #[case(vec![("host", "example.com:65536")], true)]
    #[case(vec![("host", "example.com:abc")], true)]
    #[case(vec![("host", "example.com:")], true)]
    #[case(vec![("host", "[::1]:443")], false)]
    #[case(vec![("host", "[::1]")], false)]
    #[case(vec![("host", "[::1]:-1")], true)]
    #[case(vec![("host", "fe80::1")], false)]
    #[case(vec![("host", "fe80::1:80")], true)]
    #[case(vec![("host", "fe80::abcd:8080")], true)]
    #[case(vec![("host", "1.2.3.4:80")], false)]
    #[case(vec![("host", "fe80::1:")], false)]
    #[case(vec![("host", "user:pass@example.com")], true)]
    #[case(vec![("host", "user@example.com:80")], true)]
    #[case(vec![("host", "user:pass@[::1]:80")], true)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientHostHeaderSyntax;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
