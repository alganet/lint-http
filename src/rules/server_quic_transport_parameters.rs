// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! QUIC transport parameter validation for HTTP/3 (RFC 9000 §18.2).
//!
//! Checks that the negotiated QUIC transport parameters are reasonable for
//! HTTP/3 usage:
//! - `initial_max_streams_bidi` must be non-zero so that at least one
//!   request stream can be opened.
//! - `initial_max_data` (connection-level flow control) must be non-zero.
//! - `max_idle_timeout_ms` should be set (non-zero) and not excessively large.
//! - Per-stream flow-control windows (`initial_max_stream_data_*`) must be
//!   non-zero.

use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
use crate::rules::{ProtocolRule, RuleConfig};

pub struct ServerQuicTransportParameters;

/// Maximum idle timeout (in milliseconds) above which a violation is raised.
/// 10 minutes is generous; RFC 9114 does not mandate a ceiling but very
/// large timeouts waste server resources for idle connections.
const MAX_REASONABLE_IDLE_TIMEOUT_MS: u64 = 600_000;

impl ProtocolRule for ServerQuicTransportParameters {
    type Config = RuleConfig;

    fn id(&self) -> &'static str {
        "server_quic_transport_parameters"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        _history: &ProtocolEventHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let params = match &event.kind {
            ProtocolEventKind::QuicTransportParams { params } => params,
            _ => return None,
        };

        // RFC 9000 §18.2 / RFC 9114 §3.1: HTTP/3 requires at least one
        // bidirectional stream for request/response exchange.
        if params.initial_max_streams_bidi == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_streams_bidi is 0; HTTP/3 requires at least one \
                     bidirectional stream for request/response exchange (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // Connection-level flow control window must allow data transfer.
        if params.initial_max_data == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_data is 0; no data can be transferred on this \
                     connection (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // Per-stream flow control: bidirectional local.
        if params.initial_max_stream_data_bidi_local == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_bidi_local is 0; bidirectional streams \
                     cannot carry data (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // Per-stream flow control: bidirectional remote.
        if params.initial_max_stream_data_bidi_remote == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_bidi_remote is 0; bidirectional streams \
                     cannot carry data (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // Per-stream flow control: unidirectional (control stream, QPACK, etc.).
        if params.initial_max_stream_data_uni == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_uni is 0; HTTP/3 unidirectional streams \
                     (control, QPACK) cannot carry data (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // Idle timeout: absent (None or Some(0)) means no timeout — warn
        // because idle connections consume resources indefinitely.
        match params.max_idle_timeout_ms {
            Some(0) | None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "QUIC max_idle_timeout is 0 or absent; connections may remain \
                         idle indefinitely, consuming server resources (RFC 9000 §18.2)"
                        .into(),
                });
            }
            Some(ms) if ms > MAX_REASONABLE_IDLE_TIMEOUT_MS => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "QUIC max_idle_timeout is {}ms (>{} ms); excessively large idle \
                         timeouts waste server resources (RFC 9000 §18.2)",
                        ms, MAX_REASONABLE_IDLE_TIMEOUT_MS
                    ),
                });
            }
            _ => {}
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::{
        ProtocolEvent, ProtocolEventHistory, ProtocolEventKind, QuicTransportParameters,
    };
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

    fn make_event(params: QuicTransportParameters) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: base_ts(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::QuicTransportParams { params },
        }
    }

    fn reasonable_params() -> QuicTransportParameters {
        QuicTransportParameters {
            initial_max_streams_bidi: Some(256),
            initial_max_data: Some(4_194_304),
            max_idle_timeout_ms: Some(30_000),
            initial_max_stream_data_bidi_local: Some(1_048_576),
            initial_max_stream_data_bidi_remote: Some(1_048_576),
            initial_max_stream_data_uni: Some(1_048_576),
        }
    }

    // ── Reasonable parameters pass ──────────────────────────────────────

    #[test]
    fn reasonable_params_pass() {
        let rule = ServerQuicTransportParameters;
        let evt = make_event(reasonable_params());
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── initial_max_streams_bidi ────────────────────────────────────────

    #[test]
    fn zero_bidi_streams_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_streams_bidi = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("initial_max_streams_bidi"));
    }

    #[test]
    fn one_bidi_stream_passes() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_streams_bidi = Some(1);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn absent_bidi_streams_passes() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_streams_bidi = None;
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── initial_max_data ────────────────────────────────────────────────

    #[test]
    fn zero_max_data_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_data = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("initial_max_data"));
    }

    #[test]
    fn absent_max_data_passes() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_data = None;
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── initial_max_stream_data_bidi_local ──────────────────────────────

    #[test]
    fn zero_stream_data_bidi_local_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_stream_data_bidi_local = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result
            .unwrap()
            .message
            .contains("initial_max_stream_data_bidi_local"));
    }

    // ── initial_max_stream_data_bidi_remote ─────────────────────────────

    #[test]
    fn zero_stream_data_bidi_remote_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_stream_data_bidi_remote = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result
            .unwrap()
            .message
            .contains("initial_max_stream_data_bidi_remote"));
    }

    // ── initial_max_stream_data_uni ─────────────────────────────────────

    #[test]
    fn zero_stream_data_uni_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.initial_max_stream_data_uni = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result
            .unwrap()
            .message
            .contains("initial_max_stream_data_uni"));
    }

    // ── max_idle_timeout ────────────────────────────────────────────────

    #[test]
    fn zero_idle_timeout_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.max_idle_timeout_ms = Some(0);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("max_idle_timeout"));
    }

    #[test]
    fn absent_idle_timeout_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.max_idle_timeout_ms = None;
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("max_idle_timeout"));
    }

    #[test]
    fn excessive_idle_timeout_fails() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.max_idle_timeout_ms = Some(MAX_REASONABLE_IDLE_TIMEOUT_MS + 1);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        let msg = result.unwrap().message;
        assert!(msg.contains("excessively large"));
    }

    #[test]
    fn idle_timeout_at_boundary_passes() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.max_idle_timeout_ms = Some(MAX_REASONABLE_IDLE_TIMEOUT_MS);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn small_idle_timeout_passes() {
        let rule = ServerQuicTransportParameters;
        let mut p = reasonable_params();
        p.max_idle_timeout_ms = Some(1);
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Unrelated events ignored ────────────────────────────────────────

    #[test]
    fn non_quic_event_ignored() {
        let rule = ServerQuicTransportParameters;
        let evt = ProtocolEvent {
            timestamp: base_ts(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::H3StreamOpened { stream_id: 0 },
        };
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn websocket_event_ignored() {
        let rule = ServerQuicTransportParameters;
        let evt = ProtocolEvent {
            timestamp: base_ts(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: Uuid::new_v4(),
                direction: crate::websocket_session::MessageDirection::Client,
                fin: true,
                opcode: 1,
                rsv: 0,
                payload_length: 10,
            },
        };
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    // ── Config validation ───────────────────────────────────────────────

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_quic_transport_parameters");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    // ── All-absent parameters pass (no assertions possible) ─────────────

    #[test]
    fn all_absent_params_warn_only_idle_timeout() {
        let rule = ServerQuicTransportParameters;
        let p = QuicTransportParameters {
            initial_max_streams_bidi: None,
            initial_max_data: None,
            max_idle_timeout_ms: None,
            initial_max_stream_data_bidi_local: None,
            initial_max_stream_data_bidi_remote: None,
            initial_max_stream_data_uni: None,
        };
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        // Only max_idle_timeout triggers because None means no timeout
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("max_idle_timeout"));
    }

    // ── Priority: first failing check wins ──────────────────────────────

    #[test]
    fn multiple_violations_reports_first() {
        let rule = ServerQuicTransportParameters;
        let p = QuicTransportParameters {
            initial_max_streams_bidi: Some(0),
            initial_max_data: Some(0),
            max_idle_timeout_ms: Some(0),
            initial_max_stream_data_bidi_local: Some(0),
            initial_max_stream_data_bidi_remote: Some(0),
            initial_max_stream_data_uni: Some(0),
        };
        let evt = make_event(p);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        // First check is initial_max_streams_bidi
        assert!(result.unwrap().message.contains("initial_max_streams_bidi"));
    }
}
