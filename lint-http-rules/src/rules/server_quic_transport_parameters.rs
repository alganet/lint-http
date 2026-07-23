// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! QUIC transport parameter validation for HTTP/3 (RFC 9000 §18.2).
//!
//! Checks that the QUIC transport parameters carried by a `QuicTransportParams`
//! event are reasonable for HTTP/3 usage. Each check flags only an outright 0;
//! its spec grounding differs by parameter:
//! - `initial_max_streams_bidi` (request-stream count) and
//!   `initial_max_stream_data_bidi_remote` (the window for those peer-initiated
//!   request streams) — RFC 9114 §6.1's SHOULD.
//! - `initial_max_stream_data_uni` (control/QPACK windows) — RFC 9114 §6.2.
//! - `initial_max_stream_data_bidi_local` — server-initiated bidi, which HTTP/3
//!   does not use (§6.1), so this is a reasonableness heuristic.
//! - `initial_max_data` (connection flow control) and `max_idle_timeout_ms` —
//!   reasonableness heuristics; RFC 9000 §18.2 permits 0/absent (raisable via
//!   MAX_DATA, and a 0 idle timeout legally disables the timeout).
//!
//! Everything here is SHOULD-level or softer: the rule flags an explicit 0 — the
//! functional breaker — not an absent (`None`) value, and not the §6.1 floor of
//! 100 request streams. These tolerances are deliberate.
//!
//! Scope: the only `QuicTransportParams` event the proxy currently produces
//! carries the parameters **it advertises** on its own client-facing HTTP/3 leg
//! (tagged `MessageDirection::Client`). The QUIC library (quinn) exposes no
//! API to read a *peer's* transport parameters, so an origin's parameters on the
//! upstream leg are not observable and are therefore not validated here — this
//! rule lints the proxy's own advertised parameters, not a remote endpoint's.
//! Reviving origin-side validation needs a QUIC stack that surfaces the peer's
//! transport parameters.

use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
use crate::rules::ProtocolRule;

pub struct ServerQuicTransportParameters;

/// Maximum idle timeout (in milliseconds) above which a violation is raised.
/// 10 minutes is generous; RFC 9114 does not mandate a ceiling but very
/// large timeouts waste server resources for idle connections.
const MAX_REASONABLE_IDLE_TIMEOUT_MS: u64 = 600_000;

impl ProtocolRule for ServerQuicTransportParameters {
    fn id(&self) -> &'static str {
        "server_quic_transport_parameters"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        _history: &ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // The event carries the contents of the quic_transport_parameters TLS
        // extension (this cite was re-homed here from the bidi check below, where
        // it did not belong — it describes the extension, not a stream rule).
        // cite(RFC 9000 § 18): "The extension_data field of the quic_transport_parameters extension defined in [QUIC-TLS] contains the QUIC transport parameters"
        let params = match &event.kind {
            ProtocolEventKind::QuicTransportParams { params, .. } => params,
            _ => return None,
        };

        // "number of permitted streams" half of §6.1's SHOULD. §18.2: a 0 (or
        // absent) grant only defers stream opening until a MAX_STREAMS frame, so
        // this is a SHOULD-level reasonableness check, not a hard requirement; it
        // flags an explicit 0 only (not None, and not the §6.1 floor of 100).
        // cite(RFC 9114 § 6.1): "In order to permit these streams to open, an HTTP/3 server SHOULD configure non-zero minimum values for the number of permitted streams and the initial stream flow-control window."
        if params.initial_max_streams_bidi == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_streams_bidi is 0; HTTP/3 requires at least one \
                     bidirectional stream for request/response exchange (RFC 9114 §6.1)"
                    .into(),
            });
        }

        // Connection-level flow control. Unlike the per-stream windows below, this
        // is *not* covered by §6.1's SHOULD (which is about stream windows), so the
        // non-zero check here is a reasonableness heuristic: §18.2 permits 0, with
        // the limit raisable via MAX_DATA. The cite is the definition, not a MUST.
        // cite(RFC 9000 § 18.2): "the initial value for the maximum amount of data that can be sent on the connection"
        if params.initial_max_data == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_data is 0; no data can be transferred on this \
                     connection (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // 0x05 is *locally* initiated bidi — i.e. server-initiated, which HTTP/3
        // does not use, so §6.1's request-stream SHOULD does not reach this window.
        // The non-zero check here is a reasonableness heuristic on a window HTTP/3
        // rarely exercises; the cite is the §18.2 definition, not a requirement.
        // cite(RFC 9000 § 18.2): "the initial flow control limit for locally initiated bidirectional streams"
        // cite(RFC 9114 § 6.1): "HTTP/3 does not use server-initiated bidirectional streams"
        if params.initial_max_stream_data_bidi_local == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_bidi_local is 0; bidirectional streams \
                     cannot carry data (RFC 9000 §18.2)"
                    .into(),
            });
        }

        // 0x06 is *peer*-initiated bidi — from the server that is the client's
        // request streams, so THIS is the "initial stream flow-control window" of
        // §6.1's SHOULD (the honest request-stream window; the count is above).
        // cite(RFC 9114 § 6.1): "In order to permit these streams to open, an HTTP/3 server SHOULD configure non-zero minimum values for the number of permitted streams and the initial stream flow-control window."
        if params.initial_max_stream_data_bidi_remote == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_bidi_remote is 0; request streams \
                     cannot carry data (RFC 9114 §6.1)"
                    .into(),
            });
        }

        // Unidirectional (0x07) windows are §6.2's domain (control, QPACK streams),
        // not §6.1's bidirectional SHOULD; a 0 window here starves those streams.
        // cite(RFC 9114 § 6.2): "Endpoints that excessively restrict the number of streams or the flow-control window of these streams will increase the chance that the remote peer reaches the limit early and becomes blocked."
        if params.initial_max_stream_data_uni == Some(0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "QUIC initial_max_stream_data_uni is 0; HTTP/3 unidirectional streams \
                     (control, QPACK) cannot carry data (RFC 9114 §6.2)"
                    .into(),
            });
        }

        // Idle timeout: 0/absent legally *disables* the timeout (§18.2), so both
        // this warning and the >10-minute ceiling (see the const) are reasonableness
        // heuristics, not spec requirements — flagging resource waste, not a MUST.
        // cite(RFC 9000 § 18.2): "Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0."
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

    fn title(&self) -> Option<&'static str> {
        Some("QUIC Transport Parameters")
    }

    fn description(&self) -> &'static str {
        "Validates that the QUIC transport parameters advertised for HTTP/3 are reasonable. The proxy emits a `QuicTransportParams` event for the parameters **it advertises on its own client-facing HTTP/3 endpoint**, and this rule checks those. It does **not** validate a remote origin's parameters on the upstream leg: the QUIC stack exposes no way to read a peer's transport parameters, so an origin's are not observable and go unchecked here. The checks:\n\n* **Bidirectional streams allowed** — `initial_max_streams_bidi` should be non-zero (RFC 9114 §6.1) so that at least one HTTP/3 request stream can be opened; only an explicit 0 is flagged, not an absent value or a value below the §6.1 floor of 100.\n* **Connection flow control** — `initial_max_data` should be non-zero so that data can actually be transferred (a reasonableness check; RFC 9000 §18.2 permits 0, raisable via MAX_DATA).\n* **Stream flow control** — the per-stream windows should be non-zero so streams can carry data: `initial_max_stream_data_bidi_remote` for the client's request streams (RFC 9114 §6.1) and `initial_max_stream_data_uni` for the control/QPACK streams (RFC 9114 §6.2). `initial_max_stream_data_bidi_local` governs server-initiated bidirectional streams, which HTTP/3 does not use, so its non-zero check is a reasonableness heuristic.\n* **Idle timeout** — `max_idle_timeout_ms` should be set (non-zero) to prevent idle connections from consuming server resources indefinitely, and should not be excessively large (>10 minutes); both are reasonableness heuristics, since 0/absent legally disables the timeout (RFC 9000 §18.2)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9000",
                section: Some("18.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2",
                note: "Transport Parameter Definitions",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1",
                note: "Bidirectional Streams — servers SHOULD grant non-zero stream and flow-control limits",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2",
                note: "Unidirectional Streams — restricting their flow-control window blocks control/QPACK",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "initial_max_streams_bidi = 256\ninitial_max_data = 4194304       (4 MiB)\nmax_idle_timeout_ms = 30000         (30 seconds)\ninitial_max_stream_data_bidi_local = 1048576   (1 MiB)\ninitial_max_stream_data_bidi_remote = 1048576  (1 MiB)\ninitial_max_stream_data_uni = 1048576          (1 MiB)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(zero bidirectional streams)"),
                snippet: "initial_max_streams_bidi = 0\n# Violation: HTTP/3 requires at least one bidirectional stream",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no idle timeout)"),
                snippet: "max_idle_timeout = 0\n# Violation: connections may remain idle indefinitely",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(excessive idle timeout)"),
                snippet: "max_idle_timeout = 3600000  (1 hour)\n# Violation: excessively large idle timeout wastes server resources",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &ServerQuicTransportParameters;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::{
        MessageDirection, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
        QuicTransportParameters,
    };
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_quic_transport_parameters",
        ])
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
            kind: ProtocolEventKind::QuicTransportParams {
                params,
                direction: MessageDirection::Client,
            },
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
                direction: crate::protocol_event::MessageDirection::Client,
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
        crate::rules::validate_rules(&cfg)?;
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
