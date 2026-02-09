// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use base64::Engine;

pub struct ClientSecWebsocketHeadersConsistency;

impl Rule for ClientSecWebsocketHeadersConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_sec_websocket_headers_consistency"
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
        // Only consider WebSocket handshake requests: GET method and Upgrade includes 'websocket'
        if tx.request.method != "GET" {
            return None;
        }

        let upgrade_hdr = crate::helpers::headers::get_header_str(&tx.request.headers, "upgrade");
        let connection_hdr =
            crate::helpers::headers::get_header_str(&tx.request.headers, "connection");

        let mut is_ws_upgrade = false;
        if let Some(up) = upgrade_hdr {
            // Use central parse_list_header helper which trims and skips empty parts
            for part in crate::helpers::headers::parse_list_header(up) {
                if part.eq_ignore_ascii_case("websocket") {
                    is_ws_upgrade = true;
                    break;
                }
            }
        }

        // If Upgrade header does not indicate websocket, ignore
        if !is_ws_upgrade {
            return None;
        }

        // Connection header must include 'Upgrade' token (case-insensitive tokens)
        if let Some(conn) = connection_hdr {
            let mut has_upgrade_token = false;
            for part in crate::helpers::headers::parse_list_header(conn) {
                if part.eq_ignore_ascii_case("upgrade") {
                    has_upgrade_token = true;
                    break;
                }
            }
            if !has_upgrade_token {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "WebSocket handshake missing required 'Connection: Upgrade' token"
                        .into(),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake missing 'Connection' header".into(),
            });
        }

        // Sec-WebSocket-Version must be present and be '13'
        if let Some(hv) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "sec-websocket-version")
        {
            if hv.trim() != "13" {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Invalid Sec-WebSocket-Version '{}'; expected '13'",
                        hv.trim()
                    ),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake missing 'Sec-WebSocket-Version' header".into(),
            });
        }

        // Sec-WebSocket-Key must be present and be base64 of 16 bytes
        if let Some(hv) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "sec-websocket-key")
        {
            // Validate base64
            match base64::engine::general_purpose::STANDARD.decode(hv.trim()) {
                Ok(bytes) => {
                    if bytes.len() != 16 {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Sec-WebSocket-Key must decode to 16 bytes".into(),
                        });
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Sec-WebSocket-Key is not valid base64".into(),
                    });
                }
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake missing 'Sec-WebSocket-Key' header".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_ws_request(headers: Vec<(&str, &str)>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[rstest]
    #[case(vec![
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    ], false)]
    #[case(vec![ // missing sec-websocket-key
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13")
    ], true)]
    #[case(vec![ // invalid base64
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "!!!notbase64!!!")
    ], true)]
    #[case(vec![ // key decodes to non-16 bytes (e.g., 'a')
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "YQ==")
    ], true)]
    #[case(vec![ // wrong version
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "8"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    ], true)]
    #[case(vec![ // missing Connection header
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    ], true)]
    fn websocket_handshake_cases(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = ClientSecWebsocketHeadersConsistency;
        let tx = make_ws_request(headers);
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert_eq!(v.is_some(), expect_violation);
    }

    #[test]
    fn non_get_request_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("upgrade", "websocket")]);
        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[test]
    fn non_websocket_upgrade_is_ignored() {
        // Upgrade: h2
        let tx = make_ws_request(vec![("upgrade", "h2"), ("connection", "Upgrade")]);
        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[test]
    fn connection_without_upgrade_token_reports_violation() {
        let tx = make_ws_request(vec![
            ("upgrade", "websocket"),
            ("connection", "keep-alive"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Connection: Upgrade"));
    }

    #[test]
    fn missing_sec_websocket_version_reports_violation() {
        let tx = make_ws_request(vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Sec-WebSocket-Version"));
    }

    #[test]
    fn whitespace_around_values_handled() {
        // Values containing extra whitespace should be trimmed and accepted
        let tx = make_ws_request(vec![
            ("upgrade", " websocket  , other"),
            ("connection", " keep-alive, Upgrade "),
            ("sec-websocket-version", " 13 "),
            ("sec-websocket-key", " dGhlIHNhbXBsZSBub25jZQ== "),
        ]);
        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[test]
    fn id_and_scope_are_correct() {
        let rule = ClientSecWebsocketHeadersConsistency;
        assert_eq!(rule.id(), "client_sec_websocket_headers_consistency");
        assert_eq!(
            crate::rules::Rule::scope(&rule),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn non_utf8_sec_websocket_key_reports_violation() {
        let mut tx = make_ws_request(vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
        ]);
        let mut hm = tx.request.headers.clone();
        hm.insert(
            "sec-websocket-key",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.request.headers = hm;

        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Sec-WebSocket-Key"));
    }

    #[test]
    fn non_utf8_upgrade_is_ignored() {
        let mut tx = make_ws_request(vec![
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let mut hm = tx.request.headers.clone();
        hm.insert("upgrade", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let rule = ClientSecWebsocketHeadersConsistency;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_sec_websocket_headers_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
