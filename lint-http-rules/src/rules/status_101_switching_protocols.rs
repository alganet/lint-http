// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Validate 101 Switching Protocols responses follow correct upgrade semantics.
///
/// Per RFC 9110 §15.2.2 a server MUST NOT send 101 unless the client requested
/// an upgrade, the response MUST include an `Upgrade` header indicating the
/// chosen protocol, and that protocol MUST have been offered by the client.
///
/// Additionally:
/// - HTTP/1.0 does not support the Upgrade mechanism (RFC 9110 §7.8).
/// - HTTP/2 forbids 101 entirely (RFC 9113 §8.6).
/// - HTTP/3 forbids 101 (already covered by `http3_status_code_valid`
///   but checked here for completeness).
/// - After a successful 101 exchange on a connection, no further HTTP messages
///   should appear (the connection has been handed off to the upgraded protocol).
pub struct Status101SwitchingProtocols;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_15_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2",
    note: "101 Switching Protocols",
};
const RFC_9110_7_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "Upgrade",
};
const RFC_9113_8_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9113",
    section: Some("8.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6",
    note: "The Upgrade Header Field (HTTP/2 forbids 101)",
};
const RFC_9114_4_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5",
    note: "HTTP Upgrade — the only place RFC 9114 mentions 101; forbids it alongside the Upgrade mechanism",
};

impl RuleMeta for Status101SwitchingProtocols {
    fn id(&self) -> &'static str {
        "status_101_switching_protocols"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validates that `101 Switching Protocols` responses follow correct HTTP upgrade semantics. The rule checks:\n\n- The client must have requested the upgrade via the `Upgrade` header; unsolicited 101 responses are a protocol violation.\n- The protocol chosen in the response `Upgrade` header must match one offered by the client.\n- 101 must not be sent for HTTP/1.0 requests (Upgrade is an HTTP/1.1+ mechanism), or over HTTP/2 or HTTP/3 where the Upgrade mechanism is not supported.\n- After a successful 101 exchange, no further HTTP messages should appear on the same connection — the connection has been handed off to the upgraded protocol."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_2_2, RFC_9110_7_8, RFC_9113_8_6, RFC_9114_4_5]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— client requests upgrade and server agrees"),
                snippet: "> GET /chat HTTP/1.1\n> Upgrade: websocket\n> Connection: Upgrade\n\n< HTTP/1.1 101 Switching Protocols\n< Upgrade: websocket\n< Connection: Upgrade",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— server declines upgrade (non-101 response)"),
                snippet: "> GET /resource HTTP/1.1\n> Upgrade: h2c\n> Connection: Upgrade\n\n< HTTP/1.1 200 OK",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— unsolicited 101 (no Upgrade in request)"),
                snippet: "> GET /resource HTTP/1.1\n\n< HTTP/1.1 101 Switching Protocols\n< Upgrade: websocket",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— protocol mismatch"),
                snippet: "> GET /chat HTTP/1.1\n> Upgrade: websocket\n> Connection: Upgrade\n\n< HTTP/1.1 101 Switching Protocols\n< Upgrade: h2c\n< Connection: Upgrade",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— 101 over HTTP/2"),
                snippet: "> GET /chat HTTP/2\n> Upgrade: websocket\n\n< HTTP/2 101 Switching Protocols\n< Upgrade: websocket",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— HTTP traffic after 101 on the same connection"),
                snippet: "// previous transaction on this connection: 101 upgrade to websocket\n\n> GET /other HTTP/1.1\n\n< HTTP/1.1 200 OK",
            },
        ]
    }
}

impl Rule for Status101SwitchingProtocols {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;

            // ── Check: HTTP traffic after a prior 101 on the same connection ──
            // The operative clause is "for a change in the application protocol being
            // used on this connection": a 101 switches the connection's protocol, so a
            // later HTTP transaction on it means the hand-off did not take. There is no
            // hard "MUST NOT send HTTP after 101"; this is derived from that switch, and
            // it is why the earlier cite quoted the wrong (introductory) half of the
            // sentence — the connection-change clause is what governs here.
            // cite(RFC 9110 § 15.2.2): "The 101 (Switching Protocols) status code indicates that the server understands and is willing to comply with the client's request, via the Upgrade header field (Section 7.8), for a change in the application protocol being used on this connection."
            if tx.connection_id.is_some() {
                for prev in history.iter() {
                    if let Some(prev_resp) = &prev.response {
                        if prev_resp.status == 101 {
                            return Some(self.cited(&RFC_9110_15_2_2, ctx.severity, "HTTP traffic after 101 Switching Protocols on the same connection; \
                                     the connection should have been handed off to the upgraded protocol"
                                        .into()));
                        }
                    }
                }
            }

            // Remaining checks only apply to 101 responses
            if resp.status != 101 {
                return None;
            }

            // ── Check: 101 on HTTP/1.0 ──
            // A 101 is the server acting on the client's Upgrade request; in HTTP/1.0 it
            // must ignore Upgrade, so it can never legitimately send a 101. This branch
            // fires on any 101 over HTTP/1.0; the cited sentence literally covers the
            // Upgrade-present case (the RFC's only "HTTP/1.0 doesn't do Upgrade" statement),
            // and a bare 101 with no Upgrade at all is illegitimate a fortiori — a 101
            // presupposes an Upgrade exchange HTTP/1.0 cannot have had.
            // cite(RFC 9110 § 7.8): "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field."
            // Both digits, not the string: this is the one gate here that needs the
            // minor version too, since HTTP/1.1 is the version that does support
            // Upgrade. Reading the digits is the same move as the two gates below,
            // which would otherwise be arguing with this line.
            if matches!(
                crate::http_version::parse(&tx.request.version),
                Ok(crate::http_version::HttpVersion { major: 1, minor: 0 })
            ) {
                return Some(self.cited(&RFC_9110_7_8, ctx.severity, "101 Switching Protocols must not be sent in response to an HTTP/1.0 request; \
                         Upgrade is not supported in HTTP/1.0 (RFC 9110 §7.8)"
                            .into()));
            }

            // ── Check: 101 on HTTP/2 ──
            // cite(RFC 9113 § 8.6): "HTTP/2 does not support the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
            // Two spellings were listed here because the value is one a writer chose
            // — this version carries no version field — and neither listing them nor
            // guessing which one arrives is the question. The major digit is.
            if crate::http_version::is_major(&tx.request.version, 2) {
                return Some(self.cited(
                    &RFC_9113_8_6,
                    ctx.severity,
                    "101 Switching Protocols must not be sent over HTTP/2 (RFC 9113 §8.6)".into(),
                ));
            }

            // ── Check: 101 on HTTP/3 ──
            // §4.5 is the only place RFC 9114 mentions 101 at all (the message said §4.1,
            // whose subject is HTTP Message Framing). Also enforced by
            // `http3_status_code_valid`; checked here for completeness.
            // cite(RFC 9114 § 4.5): "HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP]) or the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
            if crate::http_version::is_major(&tx.request.version, 3) {
                return Some(self.cited(
                    &RFC_9114_4_5,
                    ctx.severity,
                    "101 Switching Protocols must not be sent over HTTP/3 (RFC 9114 §4.5)".into(),
                ));
            }

            // ── Check: unsolicited 101 (no Upgrade in request) ──
            // get_all_header_values combines multiple Upgrade field lines into one
            // comma-separated list; the field-combining grammar (RFC 9110 §5.3) is cited
            // on the helper it calls (helpers/headers.rs), which owns that quote.
            let req_upgrade_combined =
                crate::helpers::headers::get_all_header_values(&tx.request.headers, "upgrade");
            // No request Upgrade at all: the client indicated no protocol, so the switch
            // the 101 announces is one it never invited. Same governing sentence as the
            // empty-token and protocol-mismatch checks below — the three faces of "not
            // indicated by the client" (nothing / malformed / a different protocol).
            // cite(RFC 9110 § 7.8): "A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding request's Upgrade header field."
            if req_upgrade_combined.is_none() {
                return Some(
                    self.cited(
                        &RFC_9110_7_8,
                        ctx.severity,
                        "Server sent 101 Switching Protocols but the request did not include an \
                         Upgrade header (RFC 9110 §7.8)"
                            .into(),
                    ),
                );
            }
            let req_upgrade_val = req_upgrade_combined.unwrap();

            // ── Check: 101 response missing Upgrade header ──
            // cite(RFC 9110 § 15.2.2): "The server MUST generate an Upgrade header field in the response that indicates which protocol(s) will be in effect after this response."
            let resp_upgrade_combined =
                crate::helpers::headers::get_all_header_values(&resp.headers, "upgrade");
            if resp_upgrade_combined.is_none() {
                return Some(
                    self.cited(
                        &RFC_9110_15_2_2,
                        ctx.severity,
                        "101 Switching Protocols response missing required Upgrade header \
                         (RFC 9110 §15.2.2)"
                            .into(),
                    ),
                );
            }
            let resp_upgrade_val = resp_upgrade_combined.unwrap();

            // ── Check: protocol mismatch ──
            // Protocol names carry a preferred case but are matched case-insensitively,
            // so both lists are folded to lowercase before comparison.
            // cite(RFC 9110 § 7.8): "Although protocol names are registered with a preferred case, recipients SHOULD use case-insensitive comparison when matching each protocol-name to supported protocols."
            let offered: Vec<String> = crate::helpers::list::list_members(&req_upgrade_val)
                .map(str::to_ascii_lowercase)
                .collect();

            // The response must indicate at least one chosen protocol.
            let chosen_list: Vec<String> = crate::helpers::list::list_members(&resp_upgrade_val)
                .map(str::to_ascii_lowercase)
                .collect();

            // Upgrade present but no valid tokens (e.g. " , , "): still nothing indicated.
            // cite(RFC 9110 § 7.8): "A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding request's Upgrade header field."
            if offered.is_empty() {
                return Some(
                    self.cited(
                        &RFC_9110_7_8,
                        ctx.severity,
                        "Server sent 101 Switching Protocols but the request Upgrade header \
                         contains no protocol tokens (RFC 9110 §7.8)"
                            .into(),
                    ),
                );
            }

            // An empty chosen list is a response Upgrade that indicates no protocol —
            // the same MUST-generate obligation as the missing-header check above.
            // cite(RFC 9110 § 15.2.2): "The server MUST generate an Upgrade header field in the response that indicates which protocol(s) will be in effect after this response."
            if chosen_list.is_empty() {
                return Some(
                    self.cited(
                        &RFC_9110_15_2_2,
                        ctx.severity,
                        "101 Switching Protocols response Upgrade header contains no protocol \
                         tokens (RFC 9110 §15.2.2)"
                            .into(),
                    ),
                );
            }

            // The server may choose one or more of the offered protocols, but every
            // chosen protocol must have been offered — `all` fails on the first that
            // was not, which is exactly "switch to a protocol not indicated".
            // cite(RFC 9110 § 7.8): "A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding request's Upgrade header field."
            let all_matched = chosen_list.iter().all(|c| offered.contains(c));

            if !all_matched {
                return Some(self.cited(
                    &RFC_9110_7_8,
                    ctx.severity,
                    format!(
                        "101 response Upgrade '{}' was not offered by the client's Upgrade '{}' \
                         (RFC 9110 §7.8)",
                        resp_upgrade_val.trim(),
                        req_upgrade_val.trim()
                    ),
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status101SwitchingProtocols;

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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
        )
        .is_none());
    }

    // ── Violation: unsolicited 101 ──

    #[rstest]
    fn unsolicited_101_no_upgrade_in_request() {
        let tx = make_upgrade_tx("HTTP/1.1", &[], 101, &[("upgrade", "websocket")]);
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
        )
        .unwrap();
        assert!(v.message.contains("HTTP/1.0"));
    }

    // ── Violation: HTTP/2 ──

    /// `HTTP/2` is not a version number: RFC 9110 § 2.5 writes two digits and a
    /// period, and RFC 9113 § 8.3.1 spells this version's implied number `2.0`.
    /// This test asserted the gate fired on it, which was a claim about a
    /// spelling nothing in this workspace writes and no production generates.
    /// The gate now reads the major digit, so a value that fails the production
    /// names no major version and reaches the checks below it instead — here,
    /// the ordinary 101 handshake, which this request satisfies.
    #[rstest]
    fn a_version_number_missing_its_minor_digit_names_no_major_version() {
        let tx = make_upgrade_tx(
            "HTTP/2",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[rstest]
    fn http2_dot_zero_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/2.0",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
        )
        .unwrap();
        assert!(v.message.contains("HTTP/2"));
    }

    // ── Violation: HTTP/3 ──

    #[rstest]
    fn http3_101_forbidden() {
        let tx = make_upgrade_tx(
            "HTTP/3.0",
            &[("upgrade", "websocket")],
            101,
            &[("upgrade", "websocket")],
        );
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &current,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
        )
        .unwrap();
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

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &current,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
        )
        .is_none());
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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
        let rule = Status101SwitchingProtocols;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
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

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let rule = Status101SwitchingProtocols;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &current,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols"
            ]),
        )
        .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "status_101_switching_protocols");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
