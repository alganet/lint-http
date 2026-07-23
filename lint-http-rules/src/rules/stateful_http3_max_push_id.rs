// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/3 MAX_PUSH_ID frame validation (RFC 9114 §7.2.7).
//!
//! Checks:
//! - MAX_PUSH_ID values must not decrease across the connection lifetime.
//!   Receipt of a MAX_PUSH_ID frame containing a smaller value than a
//!   previously received one MUST be treated as a connection error of
//!   type H3_ID_ERROR.

use crate::lint::Violation;
use crate::protocol_event::{
    MessageDirection, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
};
use crate::rules::ProtocolRule;

pub struct StatefulHttp3MaxPushId;

impl ProtocolRule for StatefulHttp3MaxPushId {
    fn id(&self) -> &'static str {
        "stateful_http3_max_push_id"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // The event this rule recognizes is the MAX_PUSH_ID frame itself; every
        // other protocol event is out of scope.
        // cite(RFC 9114 § 7.2.7): "The MAX_PUSH_ID frame (type=0x0d) is used by clients to control the number of server pushes that the server can initiate."
        let (current, direction) = match &event.kind {
            ProtocolEventKind::H3MaxPushId { push_id, direction } => (*push_id, *direction),
            _ => return None,
        };

        // MAX_PUSH_ID is a client-only frame: a server sending one at all is the
        // violation, whatever its value. This became checkable once the upstream
        // leg is observed with a sender direction — a `Server` MAX_PUSH_ID is one
        // the origin sent to this proxy, which as the receiving client must reject.
        // cite(RFC 9114 § 7.2.7): "A server MUST NOT send a MAX_PUSH_ID frame.  A client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED."
        if direction == MessageDirection::Server {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "HTTP/3 MAX_PUSH_ID (push_id {}) sent by a server; a server MUST NOT \
                     send MAX_PUSH_ID (RFC 9114 §7.2.7, H3_FRAME_UNEXPECTED)",
                    current
                ),
            });
        }

        // A value strictly smaller than one already received is the violation;
        // the comparison is `<`, not `<=`, because equal does not reduce the
        // maximum and is a legitimate idempotent re-send.
        // cite(RFC 9114 § 7.2.7): "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than previously received MUST be treated as a connection error of type H3_ID_ERROR"
        for prev in history.iter() {
            if let ProtocolEventKind::H3MaxPushId {
                push_id: prev_id, ..
            } = &prev.kind
            {
                if current < *prev_id {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "HTTP/3 MAX_PUSH_ID {} decreased from previous {} \
                             (RFC 9114 §7.2.7, H3_ID_ERROR)",
                            current, prev_id
                        ),
                    });
                }
                // Compare only against the most recent prior MAX_PUSH_ID. On any
                // connection that has not already violated, the running maximum
                // is the most recent value, so this is exact; the spec's
                // "previously received" only diverges from "most recent" after
                // an earlier decrease, which was itself flagged at that step.
                // Not a spec-licensed construct — a deliberate choice to avoid a
                // redundant second finding (RULECITES §4.1).
                break;
            }
        }

        // No prior MAX_PUSH_ID: the maximum is unset at connection creation, so
        // the first frame establishes it at any value (zero included) and is
        // always accepted.
        // cite(RFC 9114 § 7.2.7): "The maximum push ID is unset when an HTTP/3 connection is created, meaning that a server cannot push until it receives a MAX_PUSH_ID frame"
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 MAX_PUSH_ID Monotonicity")
    }

    fn description(&self) -> &'static str {
        "Validates HTTP/3 `MAX_PUSH_ID` frame semantics across the lifetime of a connection.  This rule inspects protocol-level events emitted by the HTTP/3 control-stream parser and checks:\n\n* **A server must not send `MAX_PUSH_ID`** — `MAX_PUSH_ID` is a client-only frame; a `MAX_PUSH_ID` observed from a server is a connection error of type `H3_FRAME_UNEXPECTED` (RFC 9114 §7.2.7), regardless of its value.\n\n* **MAX_PUSH_ID must not decrease** — when multiple `MAX_PUSH_ID` frames are received on the same connection, each successive value MUST be greater than or equal to the previous one.  Receipt of a smaller value is a connection error of type `H3_ID_ERROR` (RFC 9114 §7.2.7).\n\nThe first `MAX_PUSH_ID` on a connection establishes the initial limit and is always accepted, regardless of value (zero is valid and means the server is not allowed to push)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("7.2.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7",
                note: "`MAX_PUSH_ID` frame",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("8.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1",
                note: "HTTP/3 error codes (`H3_ID_ERROR`)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "# Client sends MAX_PUSH_ID { push_id: 0 }   (no pushes yet)\n# Client sends MAX_PUSH_ID { push_id: 10 }  (raise limit)\n# Client sends MAX_PUSH_ID { push_id: 10 }  (idempotent re-send: allowed)\n# Client sends MAX_PUSH_ID { push_id: 25 }  (raise further: allowed)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(decreasing MAX_PUSH_ID)"),
                snippet: "# Client sends MAX_PUSH_ID { push_id: 10 }\n# Client sends MAX_PUSH_ID { push_id: 4 }\n# Violation: MAX_PUSH_ID 4 decreased from previous 10 (RFC 9114 §7.2.7, H3_ID_ERROR)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(server-sent MAX_PUSH_ID)"),
                snippet: "# Server sends MAX_PUSH_ID { push_id: 5 }\n# Violation: a server MUST NOT send MAX_PUSH_ID (RFC 9114 §7.2.7, H3_FRAME_UNEXPECTED)",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &StatefulHttp3MaxPushId;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::MessageDirection;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["stateful_http3_max_push_id"])
    }

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

    fn make_max_push_id(conn: Uuid, push_id: u64) -> ProtocolEvent {
        make_event(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id,
                direction: MessageDirection::Client,
            },
        )
    }

    // ── A server MUST NOT send MAX_PUSH_ID (RFC 9114 §7.2.7) ──────────────

    #[test]
    fn server_sent_max_push_id_is_a_violation() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_event(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 5,
                direction: MessageDirection::Server,
            },
        );
        let v = rule
            .check_event(&evt, &ProtocolEventHistory::empty(), &make_config())
            .expect("a server-sent MAX_PUSH_ID must be flagged");
        assert!(v.message.contains("server"));
        assert!(v.message.contains("H3_FRAME_UNEXPECTED"));
    }

    #[test]
    fn client_sent_max_push_id_is_not_flagged_by_the_server_check() {
        // The server-only check must not fire for a normal client MAX_PUSH_ID.
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_max_push_id(conn, 5);
        assert!(rule
            .check_event(&evt, &ProtocolEventHistory::empty(), &make_config())
            .is_none());
    }

    // ── First MAX_PUSH_ID on a connection: any value is valid ────────────

    #[test]
    fn first_max_push_id_zero_passes() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_max_push_id(conn, 0);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn first_max_push_id_nonzero_passes() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_max_push_id(conn, 100);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn first_max_push_id_max_varint_passes() {
        // Maximum varint value (2^62 - 1).
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_max_push_id(conn, (1u64 << 62) - 1);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Monotonicity: increasing or equal is OK ──────────────────────────

    #[test]
    fn increasing_max_push_id_passes() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 5);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 10);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn equal_max_push_id_passes() {
        // RFC 9114 §7.2.7 forbids "smaller than" — equal is allowed.
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 7);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 7);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    // ── Monotonicity: decreasing fails ───────────────────────────────────

    #[test]
    fn decreasing_max_push_id_fails() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 10);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 4);
        let result = rule.check_event(&evt, &history, &make_config());
        let v = result.expect("expected violation");
        assert_eq!(v.rule, "stateful_http3_max_push_id");
        assert!(v.message.contains("MAX_PUSH_ID 4"));
        assert!(v.message.contains("previous 10"));
        assert!(v.message.contains("H3_ID_ERROR"));
    }

    #[test]
    fn decreasing_to_zero_fails() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 1);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 0);
        let result = rule.check_event(&evt, &history, &make_config());
        let v = result.expect("expected violation");
        assert!(v.message.contains("MAX_PUSH_ID 0"));
        assert!(v.message.contains("previous 1"));
    }

    #[test]
    fn decreasing_by_one_fails() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 100);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 99);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    // ── Multiple prior MAX_PUSH_IDs: only most recent matters ────────────

    #[test]
    fn multiple_increasing_priors_then_equal_passes() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History (newest first): 20, 10, 5
        let g1 = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 20,
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(2),
        );
        let g2 = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 10,
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let g3 = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 5,
                direction: MessageDirection::Client,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![g1, g2, g3]);
        // 20 (most recent) == 20 -> OK
        let evt = make_max_push_id(conn, 20);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn only_most_recent_prior_is_compared() {
        // History (newest first): push_id=5 (newer), push_id=50 (older).
        // The 50 → 5 decrease would have been flagged when the 5 event was
        // processed; here we verify that an incoming push_id=8 is compared
        // against the *newest* prior (5), not the oldest (50).
        // 8 ≥ 5 → OK.
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        let newer = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 5,
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let older = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 50,
                direction: MessageDirection::Client,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![newer, older]);
        let evt = make_max_push_id(conn, 8);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn most_recent_prior_decrease_is_flagged() {
        // History (newest first): 20, 5.  New event 10 < 20 → violation.
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        let newer = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 20,
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let older = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 5,
                direction: MessageDirection::Client,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![newer, older]);
        let evt = make_max_push_id(conn, 10);
        let result = rule.check_event(&evt, &history, &make_config());
        let v = result.expect("expected violation");
        assert!(v.message.contains("MAX_PUSH_ID 10"));
        assert!(v.message.contains("previous 20"));
    }

    // ── History with mixed event kinds: skip non-MAX_PUSH_ID entries ─────

    #[test]
    fn history_with_non_max_push_id_entries_is_skipped() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History: settings (newest), then prior MAX_PUSH_ID 10, then stream opened.
        let settings = make_event_at(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings: vec![(0x06, 8192)],
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(2),
        );
        let prev = make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 10,
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let stream = make_event_at(conn, ProtocolEventKind::H3StreamOpened { stream_id: 0 }, t);
        let history = ProtocolEventHistory::new(vec![settings, prev, stream]);

        // New MAX_PUSH_ID = 5 < 10 → violation; settings should be skipped.
        let evt = make_max_push_id(conn, 5);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    #[test]
    fn history_with_only_unrelated_events_passes() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        let settings = make_event_at(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings: vec![(0x06, 8192)],
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let stream = make_event_at(conn, ProtocolEventKind::H3StreamOpened { stream_id: 0 }, t);
        let history = ProtocolEventHistory::new(vec![settings, stream]);
        // No prior MAX_PUSH_ID → first one is accepted at any value.
        let evt = make_max_push_id(conn, 0);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    // ── Unrelated events ignored ─────────────────────────────────────────

    #[test]
    fn settings_event_ignored() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_event(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings: vec![(0x06, 4096)],
                direction: MessageDirection::Client,
            },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_event_ignored() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_event(
            conn,
            ProtocolEventKind::H3GoawayReceived {
                stream_id: Some(4),
                direction: MessageDirection::Client,
            },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn stream_opened_event_ignored() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_event(conn, ProtocolEventKind::H3StreamOpened { stream_id: 0 });
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn websocket_event_ignored() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let evt = make_event(
            conn,
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

    // ── Severity propagation ─────────────────────────────────────────────

    #[test]
    fn violation_propagates_configured_severity() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 10);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 5);

        for (sev, sev_str) in [
            (crate::lint::Severity::Info, "info"),
            (crate::lint::Severity::Warn, "warn"),
            (crate::lint::Severity::Error, "error"),
        ] {
            let cfg = crate::test_helpers::make_test_config_with_severity(
                "stateful_http3_max_push_id",
                sev_str,
            );
            let v = rule
                .check_event(&evt, &history, &cfg)
                .expect("expected violation");
            assert_eq!(v.severity, sev);
            assert_eq!(v.rule, "stateful_http3_max_push_id");
        }
    }

    // ── Long idempotent chain followed by decrease ───────────────────────

    #[test]
    fn long_equal_chain_then_decrease_fails() {
        // Many idempotent re-sends at 7, then a drop to 6 → violation.
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        let mut history_vec: Vec<ProtocolEvent> = Vec::new();
        for i in 0..10 {
            history_vec.push(make_event_at(
                conn,
                ProtocolEventKind::H3MaxPushId {
                    push_id: 7,
                    direction: MessageDirection::Client,
                },
                t + chrono::Duration::seconds(10 - i),
            ));
        }
        let history = ProtocolEventHistory::new(history_vec);
        let evt = make_max_push_id(conn, 6);
        let result = rule.check_event(&evt, &history, &make_config());
        let v = result.expect("expected violation");
        assert!(v.message.contains("MAX_PUSH_ID 6"));
        assert!(v.message.contains("previous 7"));
    }

    // ── Several non-MaxPushId events between two MaxPushId events ────────

    #[test]
    fn many_unrelated_events_between_max_push_ids_does_not_hide_violation() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // Newest first: settings, several stream open/close, prior MAX_PUSH_ID=15.
        let mut history_vec = vec![make_event_at(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings: vec![(0x06, 8192)],
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(100),
        )];
        for i in (1..=10).rev() {
            history_vec.push(make_event_at(
                conn,
                ProtocolEventKind::H3StreamOpened { stream_id: i * 4 },
                t + chrono::Duration::seconds(50 + i as i64),
            ));
            history_vec.push(make_event_at(
                conn,
                ProtocolEventKind::H3StreamClosed { stream_id: i * 4 },
                t + chrono::Duration::seconds(50 + i as i64 - 1),
            ));
        }
        history_vec.push(make_event_at(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 15,
                direction: MessageDirection::Client,
            },
            t,
        ));
        let history = ProtocolEventHistory::new(history_vec);
        let evt = make_max_push_id(conn, 14);
        let v = rule
            .check_event(&evt, &history, &make_config())
            .expect("expected violation");
        assert!(v.message.contains("MAX_PUSH_ID 14"));
        assert!(v.message.contains("previous 15"));
    }

    // ── Message format reference checks ──────────────────────────────────

    #[test]
    fn violation_message_cites_section_and_error_code() {
        let rule = StatefulHttp3MaxPushId;
        let conn = Uuid::new_v4();
        let prev = make_max_push_id(conn, 3);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_max_push_id(conn, 0);
        let v = rule
            .check_event(&evt, &history, &make_config())
            .expect("expected violation");
        // The message should reference RFC 9114 §7.2.7 and the H3_ID_ERROR
        // connection error code so operators can map it to the spec.
        assert!(v.message.contains("RFC 9114"));
        assert!(v.message.contains("§7.2.7"));
        assert!(v.message.contains("H3_ID_ERROR"));
    }

    // ── Config validation ────────────────────────────────────────────────

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_http3_max_push_id");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
