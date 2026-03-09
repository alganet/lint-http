// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/3 SETTINGS frame validation (RFC 9114 §7.2.4).
//!
//! Checks:
//! - SETTINGS must not be sent more than once per connection.
//! - Setting identifiers reserved from HTTP/2 (0x00, 0x02–0x05) must not
//!   appear; their receipt is a connection error of type H3_SETTINGS_ERROR
//!   (RFC 9114 §7.2.4.1).

use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
use crate::rules::{ProtocolRule, RuleConfig};

pub struct StatefulHttp3SettingsFrame;

/// Setting identifiers reserved from HTTP/2 that MUST NOT appear in HTTP/3
/// SETTINGS frames (RFC 9114 §7.2.4.1).
const RESERVED_SETTING_IDS: &[u64] = &[
    0x00, // reserved
    0x02, // SETTINGS_ENABLE_PUSH (HTTP/2 only)
    0x03, // SETTINGS_MAX_CONCURRENT_STREAMS (HTTP/2 only)
    0x04, // SETTINGS_INITIAL_WINDOW_SIZE (HTTP/2 only)
    0x05, // SETTINGS_MAX_FRAME_SIZE (HTTP/2 only)
];

impl ProtocolRule for StatefulHttp3SettingsFrame {
    type Config = RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_http3_settings_frame"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let settings = match &event.kind {
            ProtocolEventKind::H3SettingsReceived { settings } => settings,
            _ => return None,
        };

        // RFC 9114 §7.2.4: "A SETTINGS frame MUST NOT be sent more than once
        // over a connection."
        for prev in history.iter() {
            if matches!(&prev.kind, ProtocolEventKind::H3SettingsReceived { .. }) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 duplicate SETTINGS frame on the same connection (RFC 9114 §7.2.4)"
                            .into(),
                });
            }
        }

        // RFC 9114 §7.2.4.1: identifiers defined in HTTP/2 without a
        // corresponding HTTP/3 setting are reserved — their receipt MUST
        // be treated as H3_SETTINGS_ERROR.
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

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn make_config() -> RuleConfig {
        RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        }
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
        make_event(conn, ProtocolEventKind::H3SettingsReceived { settings })
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
            ProtocolEventKind::H3GoawayReceived { stream_id: Some(4) },
        );
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn max_push_id_event_ignored() {
        let rule = StatefulHttp3SettingsFrame;
        let conn = Uuid::new_v4();
        let evt = make_event(conn, ProtocolEventKind::H3MaxPushId { push_id: 10 });
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
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
