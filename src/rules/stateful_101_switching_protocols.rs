// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate 101 Switching Protocols responses follow correct upgrade semantics.
///
/// Per RFC 9110 §15.2.2 a server MUST NOT send 101 unless the client requested
/// an upgrade, the response MUST include an `Upgrade` header indicating the
/// chosen protocol, and that protocol MUST have been offered by the client.
///
/// Additionally:
/// - HTTP/1.0 does not support the Upgrade mechanism (RFC 9110 §7.8).
/// - HTTP/2 forbids 101 entirely (RFC 9113 §8.6).
/// - HTTP/3 forbids 101 (already covered by `server_http3_status_code_validity`
///   but checked here for completeness).
/// - After a successful 101 exchange on a connection, no further HTTP messages
///   should appear (the connection has been handed off to the upgraded protocol).
pub struct Stateful101SwitchingProtocols;

impl Rule for Stateful101SwitchingProtocols {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_101_switching_protocols"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;

        // ── Check: HTTP traffic after a prior 101 on the same connection ──
        if tx.connection_id.is_some() {
            for prev in history.iter() {
                if let Some(prev_resp) = &prev.response {
                    if prev_resp.status == 101 {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message:
                                "HTTP traffic after 101 Switching Protocols on the same connection; \
                                 the connection should have been handed off to the upgraded protocol"
                                    .into(),
                        });
                    }
                }
            }
        }

        // Remaining checks only apply to 101 responses
        if resp.status != 101 {
            return None;
        }

        // ── Check: 101 on HTTP/1.0 ──
        if tx.request.version == "HTTP/1.0" {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "101 Switching Protocols must not be sent in response to an HTTP/1.0 request; \
                     Upgrade is not supported in HTTP/1.0 (RFC 9110 §7.8)"
                        .into(),
            });
        }

        // ── Check: 101 on HTTP/2 ──
        if tx.request.version == "HTTP/2" || tx.request.version == "HTTP/2.0" {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "101 Switching Protocols must not be sent over HTTP/2 (RFC 9113 §8.6)"
                    .into(),
            });
        }

        // ── Check: 101 on HTTP/3 ──
        if tx.request.version == "HTTP/3" {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "101 Switching Protocols must not be sent over HTTP/3 (RFC 9114 §4.1)"
                    .into(),
            });
        }

        // ── Check: unsolicited 101 (no Upgrade in request) ──
        // Use get_all_header_values to combine multiple Upgrade header fields
        // into a single comma-separated list (RFC 9110 §5.3).
        let req_upgrade_combined =
            crate::helpers::headers::get_all_header_values(&tx.request.headers, "upgrade");
        if req_upgrade_combined.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Server sent 101 Switching Protocols but the request did not include an \
                     Upgrade header (RFC 9110 §15.2.2)"
                    .into(),
            });
        }
        let req_upgrade_val = req_upgrade_combined.unwrap();

        // ── Check: 101 response missing Upgrade header ──
        let resp_upgrade_combined =
            crate::helpers::headers::get_all_header_values(&resp.headers, "upgrade");
        if resp_upgrade_combined.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "101 Switching Protocols response missing required Upgrade header \
                     (RFC 9110 §15.2.2)"
                    .into(),
            });
        }
        let resp_upgrade_val = resp_upgrade_combined.unwrap();

        // ── Check: protocol mismatch ──
        // Collect the protocols offered by the client (case-insensitive comparison).
        let offered: Vec<String> = crate::helpers::headers::parse_list_header(&req_upgrade_val)
            .map(|t| t.trim().to_ascii_lowercase())
            .collect();

        // The response must indicate at least one chosen protocol.
        let chosen_list: Vec<String> =
            crate::helpers::headers::parse_list_header(&resp_upgrade_val)
                .map(|t| t.trim().to_ascii_lowercase())
                .collect();

        if offered.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Server sent 101 Switching Protocols but the request Upgrade header \
                     contains no protocol tokens (RFC 9110 §7.8)"
                    .into(),
            });
        }

        if chosen_list.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "101 Switching Protocols response Upgrade header contains no protocol \
                     tokens (RFC 9110 §15.2.2)"
                    .into(),
            });
        }

        // The server may choose one or more of the offered protocols.
        let all_matched = chosen_list.iter().all(|c| offered.contains(c));

        if !all_matched {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "101 response Upgrade '{}' was not offered by the client's Upgrade '{}' \
                     (RFC 9110 §15.2.2)",
                    resp_upgrade_val.trim(),
                    req_upgrade_val.trim()
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use uuid::Uuid;

    fn make_upgrade_tx(
        req_version: &str,
        req_headers: &[(&str, &str)],
        resp_status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(resp_status, &[]);
        tx.request.version = req_version.into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(req_headers);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(resp_headers);
        tx
    }

    // ── Valid cases ──

    #[rstest]
    fn valid_upgrade_to_websocket() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn valid_upgrade_to_h2c() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "h2c"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "h2c"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn valid_upgrade_case_insensitive() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "WebSocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn non_101_response_ignored() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            200,
            &[],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn no_response_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
        ]);
        tx.response = None;
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    // ── Violation: unsolicited 101 ──

    #[rstest]
    fn unsolicited_101_no_upgrade_in_request() {
        let tx = make_upgrade_tx("HTTP/1.1", &[], 101, &[("upgrade", "websocket")]);
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("did not include an Upgrade header"));
    }

    // ── Violation: missing response Upgrade ──

    #[rstest]
    fn missing_response_upgrade_header() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("missing required Upgrade header"));
    }

    // ── Violation: protocol mismatch ──

    #[rstest]
    fn upgrade_protocol_mismatch() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "h2c"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("was not offered by the client"));
    }

    // ── Violation: HTTP/1.0 ──

    #[rstest]
    fn http10_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/1.0",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("HTTP/1.0"));
    }

    // ── Violation: HTTP/2 ──

    #[rstest]
    fn http2_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/2",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("HTTP/2"));
    }

    #[rstest]
    fn http2_dot_zero_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/2.0",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("HTTP/2"));
    }

    // ── Violation: HTTP/3 ──

    #[rstest]
    fn http3_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/3",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("HTTP/3"));
    }

    // ── Violation: post-upgrade HTTP traffic ──

    #[rstest]
    fn post_upgrade_http_traffic_detected() {
        let conn_id = Uuid::new_v4();

        // Previous transaction was a successful 101 upgrade
        let mut prev = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        prev.connection_id = Some(conn_id);
        prev.sequence_number = Some(0);

        // Current transaction is normal HTTP on the same connection
        let mut current = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        current.connection_id = Some(conn_id);
        current.sequence_number = Some(1);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&current, &history, &cfg).unwrap();
        assert!(v.message.contains("HTTP traffic after 101"));
    }

    #[rstest]
    fn no_false_positive_without_connection_id() {
        // Previous transaction was 101 but no connection_id set
        let prev = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let current = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&current, &history, &cfg).is_none());
    }

    // ── Violation: multiple offered protocols, server picks one ──

    #[rstest]
    fn valid_multiple_offered_protocols() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "h2c, websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn mismatch_with_multiple_offered() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "h2c, websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "IRC/6.9"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("was not offered"));
    }

    // ── Edge cases ──

    #[rstest]
    fn upgrade_protocol_with_whitespace_matches() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", " websocket "), ("connection", "Upgrade")],
            101,
            &[("upgrade", " websocket "), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn multiple_upgrade_header_fields_combined() {
        // Client sends two separate Upgrade header fields
        let mut tx = crate::test_helpers::make_test_transaction_with_response(101, &[]);
        tx.request.version = "HTTP/1.1".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "h2c"),
            ("connection", "Upgrade"),
        ]);
        // Append a second Upgrade header field
        tx.request
            .headers
            .append("upgrade", "websocket".parse().unwrap());
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
        ]);
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    fn request_upgrade_whitespace_only_tokens_rejected() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", " , , "), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("no protocol tokens"));
    }

    #[rstest]
    fn response_upgrade_whitespace_only_tokens_rejected() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", " , , "), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("no protocol tokens"));
    }

    #[rstest]
    fn response_upgrade_unknown_protocol_mismatches() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "TLS/1.0"), ("connection", "Upgrade")],
        );
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("was not offered"));
    }

    #[rstest]
    fn post_upgrade_no_violation_when_history_has_non_101() {
        let conn_id = Uuid::new_v4();
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.connection_id = Some(conn_id);
        prev.sequence_number = Some(0);

        let mut current = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        current.connection_id = Some(conn_id);
        current.sequence_number = Some(1);

        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let rule = Stateful101SwitchingProtocols;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule.check_transaction(&current, &history, &cfg).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_101_switching_protocols");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
