// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/3 SETTINGS frame validation (RFC 9114 §7.2.4).
//!
//! Checks:
//! - SETTINGS is the first frame on the control stream and is not sent
//!   subsequently *by that peer*, so a second one from the same peer on the
//!   connection is a violation (the other peer's SETTINGS is its own first frame).
//! - Reserved setting identifiers (0x00, 0x02–0x05 — the `Reserved` rows of
//!   Table 3 in RFC 9114 §11.2.2) must not appear; their receipt is a
//!   connection error of type H3_SETTINGS_ERROR (RFC 9114 §7.2.4.1).
//! - No setting identifier appears more than once within one SETTINGS frame
//!   (RFC 9114 §7.2.4).

use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
use crate::rules::ProtocolRule;

pub struct StatefulHttp3SettingsFrame;

/// The `Reserved` rows of the "HTTP/3 Settings" registry, transcribed from
/// RFC 9114 Table 3 (§11.2.2).  Table 3 — not §7.2.4.1's "defined in [HTTP/2]"
/// sentence — is what this list transcribes: `0x00` is reserved by the registry
/// but was never an HTTP/2 setting, so only the table covers all five values.
// cite(RFC 9114 § 11.2.2): "The entries in Table 3 are registered by this document"
const RESERVED_SETTING_IDS: &[u64] = &[
    0x00, // Reserved (no HTTP/2 counterpart)
    0x02, // Reserved (SETTINGS_ENABLE_PUSH in HTTP/2)
    0x03, // Reserved (SETTINGS_MAX_CONCURRENT_STREAMS in HTTP/2)
    0x04, // Reserved (SETTINGS_INITIAL_WINDOW_SIZE in HTTP/2)
    0x05, // Reserved (SETTINGS_MAX_FRAME_SIZE in HTTP/2)
];

impl ProtocolRule for StatefulHttp3SettingsFrame {
    fn id(&self) -> &'static str {
        "stateful_http3_settings_frame"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // The event this rule recognizes is the SETTINGS frame itself; every
        // other protocol event is out of scope.
        // cite(RFC 9114 § 7.2.4): "The SETTINGS frame (type=0x04) conveys configuration parameters that affect how endpoints communicate"
        let (settings, direction) = match &event.kind {
            ProtocolEventKind::H3SettingsReceived {
                settings,
                direction,
            } => (settings, *direction),
            _ => return None,
        };

        // Scanning the whole connection history — rather than a single stream —
        // is what makes a second SETTINGS visible at all.
        // cite(RFC 9114 § 7.2.4): "SETTINGS frames always apply to an entire HTTP/3 connection, never a single stream"
        //
        // A prior SETTINGS *from the same peer* means this one was sent
        // subsequently, which is the violation. The rule is per peer ("by each
        // peer"), so the other peer's SETTINGS — now observable on the upstream
        // leg — is its own legitimate first frame, not a duplicate of this one.
        // cite(RFC 9114 § 7.2.4): "A SETTINGS frame MUST be sent as the first frame of each control stream (see Section 6.2.1) by each peer, and it MUST NOT be sent subsequently"
        for prev in history.iter() {
            if let ProtocolEventKind::H3SettingsReceived {
                direction: prev_dir,
                ..
            } = &prev.kind
            {
                if *prev_dir != direction {
                    continue;
                }
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 duplicate SETTINGS frame from the same peer on one connection \
                         (RFC 9114 §7.2.4)"
                            .into(),
                });
            }
        }

        // Receipt of any reserved identifier is the violation; the sender was
        // forbidden from putting it on the wire.
        // cite(RFC 9114 § 7.2.4.1): "These reserved settings MUST NOT be sent, and their receipt MUST be treated as a connection error of type H3_SETTINGS_ERROR"
        for &(id, _) in settings {
            if RESERVED_SETTING_IDS.contains(&id) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 SETTINGS contains reserved HTTP/2 setting identifier \
                         0x{:02X} (RFC 9114 §7.2.4.1)",
                        id
                    ),
                });
            }
        }

        // A setting identifier repeated within the one frame is a violation the
        // sender committed; the receiver MAY reject it, but the MUST NOT is on
        // the sender, so we report it.  Checked after the per-identifier scan so
        // a reserved identifier is named for what it is even when repeated.
        // cite(RFC 9114 § 7.2.4): "The same setting identifier MUST NOT occur more than once in the SETTINGS frame"
        for (i, &(id, _)) in settings.iter().enumerate() {
            if settings[..i].iter().any(|&(prev_id, _)| prev_id == id) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 SETTINGS contains setting identifier 0x{:02X} more \
                         than once (RFC 9114 §7.2.4)",
                        id
                    ),
                });
            }
        }

        // Identifiers outside the reserved set — including the 0x1f*N+0x21
        // greasing values and unregistered extensions — pass without comment.
        // cite(RFC 9114 § 7.2.4): "An implementation MUST ignore any parameter with an identifier it does not understand"
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 SETTINGS Frame")
    }

    fn description(&self) -> &'static str {
        "Validates HTTP/3 SETTINGS frame semantics on the control stream.  This rule inspects protocol-level events emitted by the QUIC stream wrapper and checks:\n\n* **No duplicate SETTINGS** — a SETTINGS frame MUST be sent as the first frame of each control stream by each peer, and it MUST NOT be sent subsequently (RFC 9114 §7.2.4).  SETTINGS applies to the entire connection, never a single stream, so a second `H3SettingsReceived` event *from the same peer* on the connection is a violation.  Because the obligation is per peer, the other peer's SETTINGS (observable on the upstream leg) is its own legitimate first frame, not a duplicate.\n* **No reserved setting identifiers** — the `Reserved` rows of the \"HTTP/3 Settings\" registry (RFC 9114 Table 3, §11.2.2) MUST NOT be sent, and their receipt MUST be treated as a connection error of type `H3_SETTINGS_ERROR` (RFC 9114 §7.2.4.1).  The reserved identifiers are `0x00` (no HTTP/2 counterpart), `0x02` (SETTINGS_ENABLE_PUSH in HTTP/2), `0x03` (SETTINGS_MAX_CONCURRENT_STREAMS), `0x04` (SETTINGS_INITIAL_WINDOW_SIZE), and `0x05` (SETTINGS_MAX_FRAME_SIZE).\n\n* **No repeated setting identifier** — the same setting identifier MUST NOT occur more than once in the SETTINGS frame (RFC 9114 §7.2.4).  A receiver MAY treat duplicates as a connection error of type `H3_SETTINGS_ERROR`; the sender's obligation is unconditional, so a repeated identifier within one frame is a violation.\n\nIdentifiers outside the reserved set — including the `0x1f * N + 0x21` greasing values and unregistered extensions — are ignored, per RFC 9114 §7.2.4's requirement that unknown parameters be ignored."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("7.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4",
                note: "SETTINGS",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("7.2.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1",
                note: "Defined SETTINGS Parameters",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("11.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-11.2.2",
                note: "Settings Parameters (Table 3: the Reserved rows)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "# Control stream sends SETTINGS:\n#   SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 8192\n#   SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = 4096\n#   SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = 100\n# No further SETTINGS frames on this connection",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(duplicate SETTINGS)"),
                snippet: "# Control stream sends SETTINGS { 0x06 = 8192 }\n# Control stream sends SETTINGS { 0x06 = 4096 }\n# Violation: duplicate SETTINGS frame on the same connection (RFC 9114 §7.2.4)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(reserved HTTP/2 setting identifier)"),
                snippet: "# Control stream sends SETTINGS { 0x03 = 100 }\n# Violation: SETTINGS contains reserved HTTP/2 setting identifier 0x03 (RFC 9114 §7.2.4.1)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(repeated setting identifier)"),
                snippet: "# Control stream sends SETTINGS { 0x06 = 8192, 0x06 = 4096 }\n# Violation: SETTINGS contains setting identifier 0x06 more than once (RFC 9114 §7.2.4)",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &StatefulHttp3SettingsFrame;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::MessageDirection;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["stateful_http3_settings_frame"])
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

    fn make_settings(conn: Uuid, settings: Vec<(u64, u64)>) -> ProtocolEvent {
        make_event(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings,
                direction: MessageDirection::Client,
            },
        )
    }

    fn make_server_settings(conn: Uuid, settings: Vec<(u64, u64)>) -> ProtocolEvent {
        make_event(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings,
                direction: MessageDirection::Server,
            },
        )
    }

    #[test]
    fn other_peers_settings_is_not_a_duplicate() {
        // The SETTINGS rule is per peer: a server SETTINGS following a client
        // SETTINGS on one connection is the server's own first frame, not a
        // duplicate of the client's.
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let prior_client = make_settings(conn, vec![(0x06, 4096)]);
        let history = ProtocolEventHistory::new(vec![prior_client]);
        let evt = make_server_settings(conn, vec![(0x06, 8192)]);
        assert!(rule.check_event(&evt, &history, &make_config()).is_none());
    }

    // ── First SETTINGS on a connection: valid cases ──────────────────

    #[test]
    fn first_settings_with_known_ids_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(
            conn,
            vec![
                (0x06, 8192), // SETTINGS_MAX_FIELD_SECTION_SIZE
                (0x01, 4096), // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                (0x07, 100),  // SETTINGS_QPACK_BLOCKED_STREAMS
            ],
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn first_settings_empty_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn first_settings_with_unknown_extension_ids_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        // Extension/unknown setting identifiers are allowed.
        let evt = make_settings(conn, vec![(0x33, 1), (0xFF00, 42)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Duplicate SETTINGS ───────────────────────────────────────────

    #[test]
    fn duplicate_settings_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let prev = make_settings(conn, vec![(0x06, 4096)]);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_settings(conn, vec![(0x06, 8192)]);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("duplicate SETTINGS"));
    }

    #[test]
    fn duplicate_settings_both_empty_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let prev = make_settings(conn, vec![]);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_settings(conn, vec![]);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("duplicate SETTINGS"));
    }

    #[test]
    fn settings_after_other_events_no_prior_settings_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History contains stream events but no prior SETTINGS.
        let opened = make_event_at(
            conn,
            ProtocolEventKind::H3StreamOpened { stream_id: 0 },
            t + chrono::Duration::seconds(1),
        );
        let closed = make_event_at(conn, ProtocolEventKind::H3StreamClosed { stream_id: 0 }, t);
        let history = ProtocolEventHistory::new(vec![opened, closed]);
        let evt = make_settings(conn, vec![(0x06, 4096)]);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn settings_with_prior_settings_among_other_events_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let t = base_ts();
        // History: stream opened (newest), then prior SETTINGS.
        let opened = make_event_at(
            conn,
            ProtocolEventKind::H3StreamOpened { stream_id: 0 },
            t + chrono::Duration::seconds(2),
        );
        let prev_settings = make_event_at(
            conn,
            ProtocolEventKind::H3SettingsReceived {
                settings: vec![(0x06, 4096)],
                direction: MessageDirection::Client,
            },
            t + chrono::Duration::seconds(1),
        );
        let transport = make_event_at(
            conn,
            ProtocolEventKind::QuicTransportParams {
                params: crate::protocol_event::QuicTransportParameters {
                    initial_max_streams_bidi: None,
                    initial_max_data: None,
                    max_idle_timeout_ms: None,
                    initial_max_stream_data_bidi_local: None,
                    initial_max_stream_data_bidi_remote: None,
                    initial_max_stream_data_uni: None,
                },
                direction: MessageDirection::Client,
            },
            t,
        );
        let history = ProtocolEventHistory::new(vec![opened, prev_settings, transport]);
        let evt = make_settings(conn, vec![(0x06, 8192)]);
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
    }

    // ── Reserved HTTP/2 setting identifiers ──────────────────────────

    #[test]
    fn reserved_id_0x00_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x00, 0)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x00"));
    }

    #[test]
    fn reserved_id_0x02_enable_push_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x02, 1)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x02"));
    }

    #[test]
    fn reserved_id_0x03_max_concurrent_streams_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x03, 100)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x03"));
    }

    #[test]
    fn reserved_id_0x04_initial_window_size_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x04, 65535)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x04"));
    }

    #[test]
    fn reserved_id_0x05_max_frame_size_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x05, 16384)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x05"));
    }

    #[test]
    fn reserved_id_among_valid_ids_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        // Mix valid settings with one reserved.
        let evt = make_settings(conn, vec![(0x06, 8192), (0x03, 100), (0x07, 50)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x03"));
    }

    // ── Repeated setting identifier within one frame ─────────────────

    #[test]
    fn repeated_identifier_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x06, 8192), (0x06, 4096)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        let msg = result.unwrap().message;
        assert!(msg.contains("more than once"));
        assert!(msg.contains("0x06"));
    }

    #[test]
    fn repeated_identifier_non_adjacent_fails() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        // Same identifier repeated with an unrelated one between.
        let evt = make_settings(conn, vec![(0x01, 4096), (0x07, 100), (0x01, 2048)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("0x01"));
    }

    #[test]
    fn distinct_identifiers_with_equal_values_pass() {
        // Repeated *values* are fine; only repeated identifiers are a violation.
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x06, 100), (0x01, 100), (0x07, 100)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn reserved_identifier_reported_before_repeat() {
        // A repeated reserved identifier is named as reserved, not as a repeat:
        // the reserved scan runs first so the more specific violation wins.
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x03, 1), (0x03, 2)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        let msg = result.unwrap().message;
        assert!(msg.contains("reserved"));
        assert!(msg.contains("0x03"));
    }

    // ── Setting ID boundaries ────────────────────────────────────────

    #[test]
    fn setting_id_0x01_qpack_max_table_capacity_passes() {
        // 0x01 is not reserved — it's a valid HTTP/3 setting.
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x01, 4096)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn setting_id_0x06_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x06, 8192)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn setting_id_0x07_qpack_blocked_streams_passes() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x07, 200)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn setting_id_0x08_enable_connect_protocol_passes() {
        // Extended CONNECT (RFC 9220).
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x08, 1)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn setting_id_0x33_h3_datagram_passes() {
        // H3_DATAGRAM (RFC 9297).
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_settings(conn, vec![(0x33, 1)]);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Unrelated events ignored ─────────────────────────────────────

    #[test]
    fn non_settings_event_ignored() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_event(conn, ProtocolEventKind::H3StreamOpened { stream_id: 0 });
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn goaway_event_ignored() {
        let rule = StatefulHttp3SettingsFrame;
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
    fn max_push_id_event_ignored() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_event(
            conn,
            ProtocolEventKind::H3MaxPushId {
                push_id: 10,
                direction: MessageDirection::Client,
            },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Duplicate check takes priority over reserved check ───────────

    #[test]
    fn duplicate_with_reserved_id_reports_duplicate() {
        // Both violations present; duplicate is checked first.
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let prev = make_settings(conn, vec![(0x06, 4096)]);
        let history = ProtocolEventHistory::new(vec![prev]);
        let evt = make_settings(conn, vec![(0x02, 1)]); // reserved + duplicate
        let result = rule.check_event(&evt, &history, &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("duplicate SETTINGS"));
    }

    // ── Config validation ────────────────────────────────────────────

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_http3_settings_frame");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
