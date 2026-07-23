// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/3 GOAWAY semantics validation (RFC 9114 §5.2).
//!
//! Checks that GOAWAY frames follow the protocol rules:
//! - The stream ID in a GOAWAY frame MUST NOT increase relative to a
//!   previously received GOAWAY on the same connection.
//! - After a GOAWAY is received, no new streams with IDs beyond the
//!   indicated last stream ID should be initiated.

use crate::lint::Violation;
use crate::protocol_event::{
    MessageDirection, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
};
use crate::rules::ProtocolRule;

pub struct StatefulHttp3GoawaySemantics;

impl ProtocolRule for StatefulHttp3GoawaySemantics {
    fn id(&self) -> &'static str {
        "stateful_http3_goaway_semantics"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // cite(RFC 9114 § 7.2.6): "The GOAWAY frame (type=0x07) is used to initiate graceful shutdown of an HTTP/3 connection by either endpoint."
        match &event.kind {
            // RFC 9114 §5.2: the identifier in a GOAWAY frame MUST NOT
            // increase beyond the value sent in a previous GOAWAY.
            ProtocolEventKind::H3GoawayReceived {
                stream_id: current_id,
                direction: current_dir,
            } => {
                for prev in history.iter() {
                    if let ProtocolEventKind::H3GoawayReceived {
                        stream_id: prev_id,
                        direction: prev_dir,
                    } = &prev.kind
                    {
                        // Compare only same-sender GOAWAYs: a server's identifier
                        // is a request stream ID, a client's is a push ID — two
                        // different id spaces, so monotonicity holds within each.
                        // cite(RFC 9114 § 5.2): "The server sends a client-initiated bidirectional stream ID; the client sends a push ID."
                        if current_dir != prev_dir {
                            continue;
                        }
                        // A later identifier above an earlier one is the error;
                        // `>` (not `>=`) because re-sending the same value is
                        // allowed.
                        // cite(RFC 9114 § 5.2): "Receiving a GOAWAY containing a larger identifier than previously received MUST be treated as a connection error of type H3_ID_ERROR."
                        if let (Some(curr), Some(prev)) = (current_id, prev_id) {
                            if curr > prev {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "HTTP/3 GOAWAY identifier {} increased from previous {} \
                                         (RFC 9114 §5.2)",
                                        curr, prev
                                    ),
                                });
                            }
                        }
                        break; // Only check the most recent prior same-sender GOAWAY
                    }
                }
                None
            }

            // After a *server* GOAWAY with a known stream ID, no request streams
            // beyond that ID should open. Only a server GOAWAY carries a request
            // stream ID comparable to an opened stream; a client GOAWAY's push ID
            // is a different space, so scoping to server GOAWAYs is what makes
            // this check valid. A `None` id or a non-server GOAWAY is skipped.
            ProtocolEventKind::H3StreamOpened { stream_id } => {
                for prev in history.iter() {
                    if let ProtocolEventKind::H3GoawayReceived {
                        stream_id: goaway_id,
                        direction,
                    } = &prev.kind
                    {
                        // cite(RFC 9114 § 5.2): "The server sends a client-initiated bidirectional stream ID; the client sends a push ID."
                        if *direction != MessageDirection::Server {
                            continue;
                        }
                        // Opening a request stream at or beyond the server's
                        // last-processed stream ID is initiating a new request
                        // after the GOAWAY, which the endpoint must not do.
                        // cite(RFC 9114 § 5.2): "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of a GOAWAY frame from the peer."
                        if let Some(goaway_id) = goaway_id {
                            if stream_id > goaway_id {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "HTTP/3 stream {} opened after server GOAWAY with last \
                                         stream ID {} (RFC 9114 §5.2)",
                                        stream_id, goaway_id
                                    ),
                                });
                            }
                        }
                        break; // Only the most recent server GOAWAY sets the limit
                    }
                }
                None
            }

            _ => None,
        }
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 GOAWAY Semantics")
    }

    fn description(&self) -> &'static str {
        "Validates HTTP/3 GOAWAY frame semantics during connection lifecycle.  A GOAWAY's identifier depends on who sent it: a server sends a client-initiated request stream ID, a client sends a push ID (RFC 9114 §5.2), so the checks below are scoped by sender.  This rule inspects protocol-level events and checks:\n\n* **GOAWAY identifier must not increase** — when multiple GOAWAY frames are received from the same peer on a connection, the identifier in each subsequent GOAWAY MUST NOT be greater than the previous one (RFC 9114 §5.2).\n* **No request streams beyond a server GOAWAY limit** — after a *server* GOAWAY (whose identifier is a request stream ID), no new request stream should be opened with an ID greater than the indicated last stream ID (RFC 9114 §5.2).  A client GOAWAY carries a push ID and does not constrain request streams."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9114",
            section: Some("5.2"),
            url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2",
            note: "Connection Shutdown (GOAWAY)",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "# Connection accepts streams 0, 4, 8\n# Server sends GOAWAY { stream_id: 8 }\n# Server sends GOAWAY { stream_id: 4 }  (allowed: decreasing)\n# Connection closes gracefully",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(increasing GOAWAY stream ID)"),
                snippet: "# Server sends GOAWAY { stream_id: 4 }\n# Server sends GOAWAY { stream_id: 12 }\n# Violation: stream ID 12 increased from previous 4 (RFC 9114 §5.2)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(stream opened beyond GOAWAY limit)"),
                snippet: "# Server sends GOAWAY { stream_id: 4 }\n# Client opens stream 8\n# Violation: stream 8 opened after GOAWAY with last stream ID 4 (RFC 9114 §5.2)",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &StatefulHttp3GoawaySemantics;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::MessageDirection;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_http3_goaway_semantics",
        ])
    }

    /// Fixed base timestamp so tests never depend on wall-clock ordering.
    fn base_ts() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn make_event_at(conn: Uuid, kind: ProtocolEventKind, ts: DateTime<Utc>) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: ts,
            connection_id: conn,
            kind,
        }
    }

    fn make_event(conn: Uuid, kind: ProtocolEventKind) -> ProtocolEvent {
        make_event_at(conn, kind, base_ts())
    }

    fn make_goaway(conn: Uuid, stream_id: Option<u64>) -> ProtocolEvent {
        make_event(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id,
                direction: MessageDirection::Client,
            },
        )
    }

    /// A server GOAWAY, whose identifier is a request stream ID — the only kind
    /// that limits how far client request streams may open.
    fn make_server_goaway(conn: Uuid, stream_id: Option<u64>) -> ProtocolEvent {
        make_event(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id,
                direction: MessageDirection::Server,
            },
        )
    }

    fn make_stream_opened(conn: Uuid, stream_id: u64) -> ProtocolEvent {
        make_event(conn, ProtocolEventKind::H3StreamOpened { stream_id })
    }

    // ── GOAWAY stream ID must not increase ──────────────────────────────

    #[test]
    fn goaway_no_prior_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let evt = make_goaway(conn, Some(4));
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_decreasing_stream_id_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, Some(10));
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, Some(4));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_equal_stream_id_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, Some(4));
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, Some(4));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_increasing_stream_id_fails() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, Some(4));
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, Some(10));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
        let msg = result.unwrap().message;
        assert!(msg.contains("increased from previous"));
        assert!(msg.contains("10"));
        assert!(msg.contains("4"));
    }

    #[test]
    fn goaway_none_after_some_passes() {
        // GOAWAY with None stream_id after one with Some — the None
        // can't be compared, so no violation.
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, Some(4));
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, None);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_some_after_none_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, None);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, Some(4));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    // ── Stream opened after GOAWAY ──────────────────────────────────────

    #[test]
    fn stream_opened_no_goaway_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let evt = make_stream_opened(conn, 0);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_opened_within_goaway_limit_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_goaway(conn, Some(10));
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 8);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_opened_at_goaway_limit_passes() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_goaway(conn, Some(10));
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 10);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_opened_beyond_goaway_limit_fails() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_server_goaway(conn, Some(4));
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 5);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
        let msg = result.unwrap().message;
        assert!(msg.contains("stream 5"));
        assert!(msg.contains("last stream ID 4"));
    }

    #[test]
    fn stream_opened_after_client_goaway_is_not_a_stream_violation() {
        // A client GOAWAY carries a *push ID*, not a request stream ID, so it
        // must not constrain how far request streams may open (the false
        // positive this scoping prevents).
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_goaway(conn, Some(4)); // client GOAWAY (push id 4)
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 5);
        assert!(rule.check_event(&evt, &history, &make_config()).is_none());
    }

    #[test]
    fn stream_opened_after_goaway_with_unknown_id_passes() {
        // GOAWAY with None stream_id means the limit is unknown — we
        // cannot determine whether the new stream exceeds it, so no
        // violation (avoids false positives).
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_goaway(conn, None);
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 0);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    // ── Unrelated events ignored ────────────────────────────────────────

    #[test]
    fn non_h3_event_ignored() {
        let rule = StatefulHttp3GoawaySemantics;
        let evt = make_event(
            Uuid::new_v4(),
            ProtocolEventKind::H3StreamClosed { stream_id: 0 },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn websocket_event_ignored() {
        let rule = StatefulHttp3GoawaySemantics;
        let evt = make_event(
            Uuid::new_v4(),
            ProtocolEventKind::WebSocketFrame {
                session_id: Uuid::new_v4(),
                direction: crate::protocol_event::MessageDirection::Client,
                fin: true,
                opcode: 1,
                rsv: 0,
                payload_length: 10,
            },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Config validation ───────────────────────────────────────────────

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_http3_goaway_semantics");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    // ── History with mixed events ───────────────────────────────────────

    #[test]
    fn goaway_check_skips_non_goaway_history() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History (newest first): goaway with id=10 at t+1, stream opened at t
        let goaway = make_event_at(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id: Some(10),
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let stream = make_event_at(conn, ProtocolEventKind::H3StreamOpened { stream_id: 2 }, t);
        let history = ProtocolEventHistory::new(vec![goaway, stream]);
        // New GOAWAY with id=12 > 10 should fail
        let evt = make_goaway(conn, Some(12));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    #[test]
    fn stream_check_skips_non_goaway_history() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History (newest first): stream closed at t+1, goaway(id=2) at t
        let closed = make_event_at(
            conn,
            ProtocolEventKind::H3StreamClosed { stream_id: 1 },
            t + chrono::Duration::seconds(1),
        );
        let goaway = make_event_at(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id: Some(2),
                direction: MessageDirection::Server,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![closed, goaway]);
        // Stream 3 > goaway id 2 — first event is H3StreamClosed which
        // should be skipped; the goaway at index 1 triggers violation.
        let evt = make_stream_opened(conn, 3);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    #[test]
    fn multiple_goaways_checks_most_recent() {
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History (newest first): goaway(6) at t+1, goaway(10) at t
        let g1 = make_event_at(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id: Some(6),
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let g2 = make_event_at(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id: Some(10),
                direction: MessageDirection::Client,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![g1, g2]);
        // New GOAWAY with id=8: compared to most recent (6), 8 > 6 → fail
        let evt = make_goaway(conn, Some(8));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    // ── Boundary edge cases (RFC 9114 §5.2) ────────────────────────────

    #[test]
    fn goaway_stream_id_zero_is_valid() {
        // GOAWAY with stream_id=0 means no streams were processed.
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let evt = make_goaway(conn, Some(0));
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_zero_at_goaway_zero_passes() {
        // Stream 0 is at the GOAWAY limit (equal), so it's allowed.
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_goaway(conn, Some(0));
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 0);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_one_beyond_goaway_zero_fails() {
        // GOAWAY with stream_id=0 means only stream 0 allowed; stream 1 is beyond.
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let goaway = make_server_goaway(conn, Some(0));
        let history = ProtocolEventHistory::new(vec![goaway]);
        let evt = make_stream_opened(conn, 1);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    #[test]
    fn goaway_decreasing_to_zero_passes() {
        // GOAWAY can decrease all the way to 0 (server retracting earlier limit).
        let rule = StatefulHttp3GoawaySemantics;
        let conn = Uuid::new_v4();
        let prev = make_goaway(conn, Some(100));
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_goaway(conn, Some(0));
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }
}
