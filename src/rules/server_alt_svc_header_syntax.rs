// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Alt-Svc` header must follow `protocol=authority` syntax (tokens per RFC tchar for protocol-id,
/// authority is host[:port] or quoted; parameters (e.g., `ma`) are allowed after a `;`).
pub struct ServerAltSvcHeaderSyntax;

impl Rule for ServerAltSvcHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_alt_svc_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("alt-svc").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Alt-Svc header contains non-UTF8 value".into(),
                    })
                }
            };

            // detect empty tokens (trailing/leading/consecutive commas)
            for raw in s.split(',') {
                if raw.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Alt-Svc contains empty token (e.g., trailing or consecutive commas)"
                                .into(),
                    });
                }
            }

            for entry in crate::helpers::headers::parse_list_header(s) {
                // split off params after first ';'
                let mut parts = entry.splitn(2, ';');
                let proto_auth = parts
                    .next()
                    .expect("splitn always yields at least one item")
                    .trim();
                if proto_auth.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Alt-Svc entry has empty protocol/authority".into(),
                    });
                }

                // expect protocol=authority
                let eq_idx = proto_auth.find('=');
                if eq_idx.is_none() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Alt-Svc entry '{}' missing '=' separating protocol and authority",
                            proto_auth
                        ),
                    });
                }

                let (protocol, auth_raw) =
                    proto_auth.split_at(eq_idx.expect("checked for none above"));
                let protocol = protocol.trim();
                let auth = auth_raw[1..].trim(); // skip '='

                if protocol.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Alt-Svc entry has empty protocol".into(),
                    });
                }

                if let Some(c) = crate::helpers::token::find_invalid_token_char(protocol) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Alt-Svc protocol id contains invalid character: '{}'", c),
                    });
                }

                // authority may be quoted; unescape quoted-string if present
                let auth_owned: Option<String> = if auth.starts_with('"') {
                    match crate::helpers::headers::unescape_quoted_string(auth) {
                        Ok(u) => Some(u),
                        Err(e) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Alt-Svc authority quoted-string invalid: {}", e),
                            })
                        }
                    }
                } else {
                    None
                };
                let auth = auth_owned.as_deref().unwrap_or(auth);

                if auth.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Alt-Svc authority is empty".into(),
                    });
                }

                // If authority contains a port, ensure port is numeric (and handle bracketed IPv6)
                if auth.starts_with('[') {
                    match crate::helpers::ipv6::parse_bracketed_ipv6(auth) {
                        Some((_inner, port_opt)) => {
                            if let Some(port_str) = port_opt {
                                if crate::helpers::ipv6::parse_port_str(port_str).is_none() {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Alt-Svc authority port is invalid: '{}'",
                                            port_str
                                        ),
                                    });
                                }
                            }
                        }
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Alt-Svc authority contains malformed IPv6 literal".into(),
                            });
                        }
                    }
                } else if auth.contains(':') {
                    if let Some(idx) = auth.rfind(':') {
                        let port_str = &auth[idx + 1..];
                        if crate::helpers::ipv6::parse_port_str(port_str).is_none() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Alt-Svc authority port is invalid: '{}'",
                                    port_str
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

    #[rstest]
    #[case(None, false)]
    #[case(Some("h2=\":443\"; ma=2592000"), false)]
    #[case(Some("h2=example.com:443"), false)]
    #[case(Some("h2=example.com:443, h3=example.com:8443"), false)]
    #[case(Some("h2=\"[::1]:443\""), false)]
    #[case(Some("h@=example.com:443"), true)]
    #[case(Some("h2=example.com:notaport"), true)]
    #[case(Some("h2=[::1"), true)]
    #[case(Some("h2=[::1]:0"), true)]
    #[case(Some("h2="), true)]
    #[case(Some(","), true)]
    #[case(Some("h2example.com:443"), true)]
    #[case(Some(";ma=1"), true)]
    fn alt_svc_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerAltSvcHeaderSyntax;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
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
    fn missing_response_returns_none() {
        let rule = ServerAltSvcHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerAltSvcHeaderSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("alt-svc", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_alt_svc_header_syntax");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerAltSvcHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
