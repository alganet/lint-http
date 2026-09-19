// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{
    RFC_9110_7_8, RFC_9113_8_6, RFC_9114_4_5, STATUS_101_IGNORED, STATUS_101_PROTOCOL_FORBIDDEN,
    STATUS_101_UNSOLICITED,
};
use crate::violations::upgrade::{RFC_9110_15_2_2, UPGRADE_101_EMPTY, UPGRADE_101_MISSING};
use crate::violations::ViolationDef;

/// Validate 101 Switching Protocols responses follow correct upgrade semantics.
///
/// Per RFC 9110 §15.2.2 a server MUST NOT send 101 unless the client requested
/// an upgrade, the response MUST include an `Upgrade` header indicating the
/// chosen protocol, and that protocol MUST have been offered by the client.
///
/// Additionally:
/// - HTTP/1.0 does not support the Upgrade mechanism (RFC 9110 §7.8).
/// - HTTP/2 forbids 101 entirely (RFC 9113 §8.6).
/// - HTTP/3 forbids 101 (RFC 9114 §4.5).
/// - After a successful 101 exchange on a connection, no further HTTP messages
///   should appear (the connection has been handed off to the upgraded protocol).
pub struct Status101SwitchingProtocols;

/// Everything this rule says, in five entries over two subjects: the `Upgrade`
/// field a 101 owes and the two ways it is not there; the status code sent on a
/// version that has no upgrade mechanism to answer; the protocol nobody offered;
/// and the connection that kept speaking HTTP after being handed off.
///
/// **This rule declares no `SpecRef` of its own.** Every sentence it names is on
/// one of these entries, in `violations/upgrade.rs` and `violations/status.rs`,
/// and `specifications()` is assembled from those — the three sections the
/// version entry holds among them, since one entry naming three documents is
/// what a per-version const would otherwise have split.
static DECLARED: &[&ViolationDef] = &[
    &UPGRADE_101_MISSING,
    &UPGRADE_101_EMPTY,
    &STATUS_101_UNSOLICITED,
    &STATUS_101_PROTOCOL_FORBIDDEN,
    &STATUS_101_IGNORED,
];

impl RuleMeta for Status101SwitchingProtocols {
    fn id(&self) -> &'static str {
        "status_101_switching_protocols"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validates that `101 Switching Protocols` responses follow correct HTTP upgrade semantics. The rule checks:\n\n- The client must have requested the upgrade via the `Upgrade` header; unsolicited 101 responses are a protocol violation.\n- The 101 itself must name what it switched to: RFC 9110 \u{a7} 15.2.2 requires an `Upgrade` header field in the response, and the requirement holds whatever the request said.\n- The protocol chosen in the response `Upgrade` header must match one offered by the client.\n- 101 must not be sent for HTTP/1.0 requests (Upgrade is an HTTP/1.1+ mechanism), or over HTTP/2 or HTTP/3 where the Upgrade mechanism is not supported.\n- After a successful 101 exchange, no further HTTP messages should appear on the same connection — the connection has been handed off to the upgraded protocol.\n\n**The client's obligation and the server's are reported separately.** They are written for different senders and neither is a measurement the other needs, so a 101 that answers a request carrying no `Upgrade` *and* names no protocol of its own draws both findings rather than the first one alone."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_2_2, RFC_9110_7_8, RFC_9113_8_6, RFC_9114_4_5]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
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
                snippet: "> GET /chat HTTP/1.1\n> Upgrade: websocket\n> Connection: Upgrade\n\n< HTTP/1.1 101 Switching Protocols\n< Upgrade: websocket\n< Connection: Upgrade\n\n> GET /other HTTP/1.1\n\n< HTTP/1.1 200 OK",
            },
        ]
    }
}

impl Rule for Status101SwitchingProtocols {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // A 101 answers for two senders, so the body collects rather than
        // returning the first thing it finds. The checks above the status gate
        // are still exclusive -- each describes a response that is not a
        // well-formed 101 at all -- and return outright; only the pair of
        // Upgrade obligations below is answered on both sides at once.
        let findings =
            || -> Vec<Violation> {
                let Some(resp) = tx.response.as_ref() else {
                    return Vec::new();
                };

                // ── Check: HTTP traffic after a prior 101 on the same connection ──
                // The operative clause is "for a change in the application protocol being
                // used on this connection": a 101 switches the connection's protocol, so a
                // later HTTP transaction on it means the hand-off did not take. There is no
                // hard "MUST NOT send HTTP after 101"; the defect is derived from what the
                // code indicates, which is the sentence quoted on the entry — and the reason
                // an earlier cite here quoted the wrong (introductory) half of it.
                //
                // The connection id is what makes the reading possible and it is optional:
                // a capture written without one produces no finding, which is a limit of the
                // capture rather than a verdict about the traffic.
                if tx.connection_id.is_some() {
                    for prev in history.iter() {
                        if let Some(prev_resp) = &prev.response {
                            if prev_resp.status == 101 {
                                return vec![ctx.report(&STATUS_101_IGNORED)];
                            }
                        }
                    }
                }

                // Remaining checks only apply to 101 responses
                if resp.status != 101 {
                    return Vec::new();
                }

                // ── Check: 101 on a version with no upgrade mechanism ──
                // One entry for all three versions, and the message is where the
                // governing section goes: the entry names three sections, so a
                // finding of it carries no citation and the version is what decides
                // which sentence it broke. The quotes are on the entry.
                //
                // HTTP/1.0 needs both digits, and it is the only one here that does:
                // HTTP/1.1 is the version that *does* support Upgrade, so the minor
                // digit is the whole difference. A 101 over HTTP/1.0 is reported
                // whether or not the request carried an `Upgrade` — the sentence
                // covers the field being present, and a 101 with no request field at
                // all is illegitimate a fortiori, since a 101 presupposes an
                // exchange HTTP/1.0 cannot have had.
                //
                // The other two read the major digit only. Two spellings of HTTP/2
                // were once listed here because the value is one a writer chose —
                // this version carries no version field of its own — and neither
                // enumerating them nor guessing which arrives is the question.
                //
                // RFC 9114 § 4.5 is the only place that document mentions 101 at
                // all. A second rule used to report the same message from the status
                // code's own side, behind a narrower gate that also required the
                // response to be HTTP/3; every finding it could make was one of
                // these, so it was deleted rather than declared beside this one.
                if matches!(
                    crate::http_version::parse(&tx.request.version),
                    Ok(crate::http_version::HttpVersion { major: 1, minor: 0 })
                ) {
                    let message = "101 Switching Protocols must not be sent in response to an \
                     HTTP/1.0 request; a server that receives an Upgrade field in an HTTP/1.0 \
                     request must ignore it (RFC 9110 §7.8)";
                    return vec![ctx.report_with(&STATUS_101_UNSOLICITED, message.into())];
                }

                if crate::http_version::is_major(&tx.request.version, 2) {
                    let message = "101 Switching Protocols must not be sent over HTTP/2, which \
                     does not support the status code (RFC 9113 §8.6)";
                    return vec![ctx.report_with(&STATUS_101_UNSOLICITED, message.into())];
                }

                if crate::http_version::is_major(&tx.request.version, 3) {
                    let message = "101 Switching Protocols must not be sent over HTTP/3, which \
                     does not support the status code or the upgrade mechanism (RFC 9114 §4.5)";
                    return vec![ctx.report_with(&STATUS_101_UNSOLICITED, message.into())];
                }

                // ── The two Upgrade obligations, one per sender ──
                // These are two requirements written for two different senders, and
                // neither is a measurement the other needs. RFC 9110 § 7.8 is about
                // the server switching to a protocol the client never indicated;
                // § 15.2.2's MUST is about the 101 naming what it switched to, and
                // it holds whatever the request said. The reading used to return on
                // the request-side finding, so a 101 defective on both sides was
                // answered about the request alone and the response's own MUST went
                // unreported -- a false negative no report showed, since the record
                // was not silent.
                //
                // At most one finding per side: the request's three faces are one
                // entry (nothing / no tokens / a protocol it did not offer) and the
                // response's two are another, so `out` gains two findings at most
                // and never the same entry twice.
                let mut out = Vec::new();

                // get_all_header_values combines multiple Upgrade field lines into one
                // comma-separated list; the field-combining grammar (RFC 9110 §5.3) is cited
                // on the helper it calls (helpers/headers.rs), which owns that quote.
                let req_upgrade_combined =
                    crate::helpers::headers::get_all_header_values(&tx.request.headers, "upgrade");
                let resp_upgrade_combined =
                    crate::helpers::headers::get_all_header_values(&resp.headers, "upgrade");

                // Protocol names carry a preferred case but are matched case-insensitively,
                // so both lists are folded to lowercase before comparison.
                // cite(RFC 9110 § 7.8): "Although protocol names are registered with a preferred case, recipients SHOULD use case-insensitive comparison when matching each protocol-name to supported protocols."
                let members = |v: &Option<String>| -> Vec<String> {
                    v.as_deref()
                        .map(|s| {
                            crate::helpers::list::list_members(s)
                                .map(str::to_ascii_lowercase)
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let offered = members(&req_upgrade_combined);
                let chosen = members(&resp_upgrade_combined);

                // The client's side. No request Upgrade at all, or one indicating no
                // protocol, are two faces of the same entry -- "not indicated by the
                // client" arriving as nothing or as a field with nothing in it -- and
                // the sentence is quoted once, on the entry.
                if req_upgrade_combined.is_none() {
                    out.push(ctx.report_with(
                    &STATUS_101_PROTOCOL_FORBIDDEN,
                    "Server sent 101 Switching Protocols but the request did not include an \
                     Upgrade header"
                        .into(),
                ));
                } else if offered.is_empty() {
                    out.push(
                        ctx.report_with(
                            &STATUS_101_PROTOCOL_FORBIDDEN,
                            "Server sent 101 Switching Protocols but the request Upgrade header \
                     contains no protocol tokens"
                                .into(),
                        ),
                    );
                }

                // The server's side, and § 15.2.2's MUST is unconditional on a 101:
                // an absent field and a present one naming no protocol both leave the
                // response saying nothing about what it switched to. Two entries
                // because the repair differs -- send the field, or put a protocol in
                // the one already sent.
                if resp_upgrade_combined.is_none() {
                    out.push(ctx.report_with(
                        &UPGRADE_101_MISSING,
                        "101 Switching Protocols response missing required Upgrade header".into(),
                    ));
                } else if chosen.is_empty() {
                    out.push(
                        ctx.report_with(
                            &UPGRADE_101_EMPTY,
                            "101 Switching Protocols response Upgrade header contains no protocol \
                     tokens"
                                .into(),
                        ),
                    );
                }

                // The third face of the request-side entry, and it is asked only when
                // both senders named something: a mismatch is a comparison, and a list
                // with no members states nothing to compare. That gate is also what
                // keeps the entry from being drawn twice -- the request-side findings
                // above fire exactly when `offered` is empty, so the two are exclusive
                // by construction.
                //
                // The server may choose one or more of the offered protocols, but every
                // chosen protocol must have been offered — `all` fails on the first that
                // was not, which is exactly "switch to a protocol not indicated" and the
                // third face of the entry's sentence.
                if !offered.is_empty()
                    && !chosen.is_empty()
                    && !chosen.iter().all(|c| offered.contains(c))
                {
                    out.push(ctx.report_with(
                        &STATUS_101_PROTOCOL_FORBIDDEN,
                        format!(
                        "101 response Upgrade '{}' was not offered by the client's Upgrade '{}'",
                        resp_upgrade_combined.as_deref().unwrap_or("").trim(),
                        req_upgrade_combined.as_deref().unwrap_or("").trim()
                    ),
                    ));
                }

                out
            };
        findings()
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

    /// Every finding the rule makes about one transaction, in order.
    ///
    /// `run_rule` takes the first of however many, so a test written on it
    /// passes whether the second finding arrived or not -- which is how the
    /// masking below survived a green suite.
    fn judge_all(tx: &crate::http_transaction::HttpTransaction) -> Vec<String> {
        let rule = Status101SwitchingProtocols;
        crate::test_helpers::run_rule_all(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_101_switching_protocols",
            ]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect()
    }

    // ── Both senders answered ──

    /// § 7.8 is about the client indicating a protocol and § 15.2.2 about the
    /// 101 naming one, so a response failing both owes two findings. It used to
    /// answer for the request and return.
    #[rstest]
    fn a_101_defective_on_both_sides_is_answered_about_both() {
        let tx = make_upgrade_tx("HTTP/1.1", &[("connection", "Upgrade")], 101, &[]);
        let mut got = judge_all(&tx);
        got.sort();
        assert_eq!(
            got,
            vec!["status_101_protocol_forbidden", "upgrade_101_missing"]
        );
    }

    /// The same seam one check further down: both fields present, neither
    /// naming a protocol.
    #[rstest]
    fn two_upgrade_fields_naming_no_protocol_are_two_findings() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", ","), ("connection", "Upgrade")],
            101,
            &[("upgrade", ",")],
        );
        let mut got = judge_all(&tx);
        got.sort();
        assert_eq!(
            got,
            vec!["status_101_protocol_forbidden", "upgrade_101_empty"]
        );
    }

    /// The other direction: answering both sides must not invent a request-side
    /// finding for a request that indicated a protocol.
    #[rstest]
    fn a_response_naming_nothing_is_not_also_the_clients_defect() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
            101,
            &[],
        );
        assert_eq!(judge_all(&tx), vec!["upgrade_101_missing"]);
    }

    /// A mismatch is the request-side entry's third face, so it must be drawn
    /// once and not beside the two the empty lists draw. The gate that makes it
    /// exclusive is `offered` being non-empty; this pins the count.
    #[rstest]
    fn a_mismatch_draws_the_entry_once() {
        let tx = make_upgrade_tx(
            "HTTP/1.1",
            &[("upgrade", "h2c"), ("connection", "Upgrade")],
            101,
            &[("upgrade", "websocket")],
        );
        assert_eq!(judge_all(&tx), vec!["status_101_protocol_forbidden"]);
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
