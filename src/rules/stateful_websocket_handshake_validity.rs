// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Verify that a WebSocket upgrade handshake response matches the request.
///
/// Although the client request is examined by `client_sec_websocket_headers_consistency`,
/// the response deserves its own validation.  A correct server handshake MUST:
///
/// * Use status `101 Switching Protocols`.
/// * Include `Connection: Upgrade` and `Upgrade: websocket` headers.
/// * Echo a properly calculated `Sec-WebSocket-Accept` value derived from the
///   client's `Sec-WebSocket-Key` (RFC 6455 §4.2.2).
///
/// This rule is classified as "stateful" in the roadmap because it requires
/// examining both the request and response portions of a transaction; however,
/// the current engine supplies both halves together, so the implementation
/// ignores the `previous` parameter.
pub struct StatefulWebsocketHandshakeValidity;

impl Rule for StatefulWebsocketHandshakeValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_websocket_handshake_validity"
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
        let req = &tx.request;

        // Only consider WebSocket handshake requests (GET + Upgrade: websocket)
        if req.method != "GET" {
            return None;
        }
        if !is_websocket_upgrade(&req.headers) {
            return None;
        }

        // If there's no response, nothing to validate here
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Response status must be 101
        if resp.status != 101 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Expected 101 Switching Protocols for WebSocket handshake but got {}",
                    resp.status
                ),
            });
        }

        // Connection header must include 'Upgrade'
        if let Some(conn) = crate::helpers::headers::get_header_str(&resp.headers, "connection") {
            let mut has_upgrade = false;
            for part in crate::helpers::headers::parse_list_header(conn) {
                if part.eq_ignore_ascii_case("upgrade") {
                    has_upgrade = true;
                    break;
                }
            }
            if !has_upgrade {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "WebSocket handshake response missing required 'Connection: Upgrade' token"
                            .into(),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake response missing 'Connection' header".into(),
            });
        }

        // Upgrade header must contain 'websocket'
        if let Some(up) = crate::helpers::headers::get_header_str(&resp.headers, "upgrade") {
            let mut found = false;
            for part in crate::helpers::headers::parse_list_header(up) {
                if part.eq_ignore_ascii_case("websocket") {
                    found = true;
                    break;
                }
            }
            if !found {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "WebSocket handshake response Upgrade header does not include 'websocket'"
                            .into(),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake response missing 'Upgrade' header".into(),
            });
        }

        // Validate Sec-WebSocket-Accept against the request's key
        let accept_hdr =
            crate::helpers::headers::get_header_str(&resp.headers, "sec-websocket-accept");
        if accept_hdr.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "WebSocket handshake response missing 'Sec-WebSocket-Accept' header"
                    .into(),
            });
        }
        let accept_val = accept_hdr.unwrap().trim();

        // grab key from request
        let key_hdr = crate::helpers::headers::get_header_str(&req.headers, "sec-websocket-key");
        if key_hdr.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Cannot verify Sec-WebSocket-Accept: request missing Sec-WebSocket-Key"
                    .into(),
            });
        }
        let key_val = key_hdr.unwrap();

        match crate::helpers::websocket::compute_accept(key_val) {
            Some(expected) => {
                if expected != accept_val {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Sec-WebSocket-Accept '{}' does not match expected '{}'",
                            accept_val, expected
                        ),
                    });
                }
            }
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "Invalid Sec-WebSocket-Key; cannot compute expected Sec-WebSocket-Accept"
                            .into(),
                });
            }
        }

        None
    }
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    if let Some(up) = crate::helpers::headers::get_header_str(headers, "upgrade") {
        for part in crate::helpers::headers::parse_list_header(up) {
            if part.eq_ignore_ascii_case("websocket") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_ws_tx(
        req_headers: Vec<(&str, &str)>,
        resp_status: u16,
        resp_headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(resp_status, &[]);
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&req_headers);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&resp_headers);
        tx
    }

    #[rstest]
    fn valid_handshake_should_pass() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", accept),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[rstest]
    fn missing_accept_header() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("missing 'Sec-WebSocket-Accept'"));
    }

    #[rstest]
    fn mismatched_accept_value() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "wrongvalue"),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("does not match expected"));
    }

    #[rstest]
    fn missing_key_in_request() {
        // the response is otherwise correct but the request never provided a key
        let tx = make_ws_tx(
            vec![("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("missing Sec-WebSocket-Key"));
    }

    #[rstest]
    fn invalid_key_in_request() {
        // include a key that fails compute_accept (non-base64)
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", "!!notbase64!!"),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "anything"),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("Invalid Sec-WebSocket-Key"));
    }

    #[rstest]
    fn accept_header_whitespace_is_trimmed() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = "  s3pPLMBiTxaQ9kYGzzhZRbK+xOo=  ";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", accept),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[rstest]
    fn wrong_status_code() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            200,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("Expected 101"));
    }

    #[rstest]
    fn missing_connection_response_header() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("missing 'Connection' header"));
    }

    #[rstest]
    fn response_upgrade_without_websocket_token() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "notwebsocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v
            .message
            .contains("Upgrade header does not include 'websocket'"));
    }

    #[rstest]
    fn non_handshake_request_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.method = "POST".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("upgrade", "websocket")]);
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[rstest]
    fn get_with_non_websocket_upgrade_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "notwebsocket"),
            ("connection", "Upgrade"),
        ]);
        // response absence doesn't matter since rule should bail early
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[rstest]
    fn handshake_request_no_response_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
        ]);
        // no response recorded
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&tx, None, &cfg).is_none());
    }

    #[rstest]
    fn response_connection_without_upgrade_token_reports_issue() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "keep-alive"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("required 'Connection: Upgrade' token"));
    }

    #[rstest]
    fn response_missing_upgrade_header_reports_issue() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
            ],
            101,
            vec![
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        );
        let rule = StatefulWebsocketHandshakeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("missing 'Upgrade' header"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_websocket_handshake_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
