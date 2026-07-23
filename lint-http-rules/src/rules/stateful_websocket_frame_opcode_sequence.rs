// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket frame opcode sequence validation (RFC 6455 §5).
//!
//! Checks message-level opcode sequencing rules:
//! - Data messages must use opcode 1 (Text) or 2 (Binary).
//! - Control frames (Close=8, Ping=9, Pong=10) must have payload ≤ 125 bytes.
//! - After a Close frame is sent in one direction, no further data frames
//!   should be sent in that direction.
//! - Reserved opcodes (3-7, 11-15) must not appear without negotiated
//!   extensions.

use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
use crate::rules::ProtocolRule;

pub struct StatefulWebsocketFrameOpcodeSequence;

impl ProtocolRule for StatefulWebsocketFrameOpcodeSequence {
    fn id(&self) -> &'static str {
        "stateful_websocket_frame_opcode_sequence"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let (session_id, direction, opcode, payload_length) = match &event.kind {
            ProtocolEventKind::WebSocketFrame {
                session_id,
                direction,
                opcode,
                payload_length,
                ..
            } => (*session_id, *direction, *opcode, *payload_length),
            _ => return None,
        };

        // Reserved opcodes (3-7, 11-15) are invalid without extensions.
        // cite(RFC 6455 § 11.8): "The opcode denotes the frame type of the WebSocket frame,"
        if (3..=7).contains(&opcode) || (11..=15).contains(&opcode) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "WebSocket reserved opcode {} used without negotiated extension (RFC 6455 §5.2)",
                    opcode
                ),
            });
        }

        // Opcode 0 (continuation) requires fragmentation context not
        // available at assembled-message level; skip for now.
        if opcode == 0 {
            return None;
        }

        // Control frames (8-10) must not exceed 125 bytes payload.
        // cite(RFC 6455 § 5.5.1): "The Close frame MAY contain a body (the "Application data" portion of the frame) that indicates a reason for closing"
        if opcode >= 8 && payload_length > 125 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "WebSocket control frame (opcode {}) payload {} bytes exceeds 125-byte limit (RFC 6455 §5.5)",
                    opcode, payload_length
                ),
            });
        }

        // After a Close frame, no data frames should follow in the same
        // direction.  Scan history for a prior Close from this direction
        // in the same session.
        if opcode == 1 || opcode == 2 {
            let has_prior_close = history.iter().any(|prev| {
                if let ProtocolEventKind::WebSocketFrame {
                    session_id: sid,
                    direction: dir,
                    opcode: op,
                    ..
                } = &prev.kind
                {
                    *sid == session_id && *dir == direction && *op == 8
                } else {
                    false
                }
            });

            if has_prior_close {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "WebSocket data frame (opcode {}) sent after Close in {:?} direction (RFC 6455 §5.5.1)",
                        opcode, direction
                    ),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("WebSocket Frame Opcode Sequence")
    }

    fn description(&self) -> &'static str {
        "Validates message-level opcode sequencing rules for WebSocket frames observed during relay.  This rule inspects each frame event and checks:\n\n* **Reserved opcodes** (3-7, 11-15) must not appear without a negotiated extension (RFC 6455 §5.2).\n* **Control frame payload limit** — Close (8), Ping (9), and Pong (10) frames must not exceed 125 bytes of payload data (RFC 6455 §5.5).\n* **Data after Close** — once a Close frame has been sent in a given direction, no further data frames (Text=1, Binary=2) should follow in that same direction (RFC 6455 §5.5.1)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
                note: "Base Framing Protocol, opcode definitions",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5",
                note: "Control Frames, payload length constraint",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1",
                note: "Close frame semantics and half-close behaviour",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\n\nHTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\n\n# After upgrade, valid frame sequence:\n# Client -> Server: opcode=1 (Text), 42 bytes\n# Server -> Client: opcode=1 (Text), 100 bytes\n# Client -> Server: opcode=8 (Close), 2 bytes\n# Server -> Client: opcode=8 (Close), 2 bytes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(reserved opcode)"),
                snippet: "# After WebSocket upgrade, client sends reserved opcode:\n# Client -> Server: opcode=5, 10 bytes\n# Opcode 5 is reserved (RFC 6455 §5.2)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(control frame too large)"),
                snippet: "# After WebSocket upgrade, client sends oversized Ping:\n# Client -> Server: opcode=9 (Ping), 200 bytes\n# Control frames must not exceed 125 bytes (RFC 6455 §5.5)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(data after close)"),
                snippet: "# After WebSocket upgrade, client sends data after Close:\n# Client -> Server: opcode=8 (Close), 2 bytes\n# Client -> Server: opcode=1 (Text), 50 bytes\n# No data frames after Close in same direction (RFC 6455 §5.5.1)",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &StatefulWebsocketFrameOpcodeSequence;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::MessageDirection;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_websocket_frame_opcode_sequence",
        ])
    }

    fn make_ws_event(
        conn: Uuid,
        session: Uuid,
        direction: MessageDirection,
        opcode: u8,
        payload_length: u64,
    ) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: conn,
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: session,
                direction,
                fin: true,
                opcode,
                rsv: 0,
                payload_length,
            },
        }
    }

    #[test]
    fn valid_text_frame_passes() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();
        let evt = make_ws_event(conn, session, MessageDirection::Client, 1, 42);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn valid_binary_frame_passes() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();
        let evt = make_ws_event(conn, session, MessageDirection::Server, 2, 1024);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn valid_control_frames_pass() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();

        for opcode in [8, 9, 10] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 10);
            let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
            assert!(result.is_none(), "opcode {} should pass", opcode);
        }
    }

    #[test]
    fn reserved_opcode_fails() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();

        for opcode in [3, 4, 5, 6, 7, 11, 12, 13, 14, 15] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 0);
            let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
            assert!(result.is_some(), "opcode {} should fail", opcode);
            assert!(result.unwrap().message.contains("reserved opcode"));
        }
    }

    #[test]
    fn control_frame_over_125_bytes_fails() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();

        // Ping with 126 bytes payload
        let evt = make_ws_event(conn, session, MessageDirection::Client, 9, 126);
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("125-byte limit"));
    }

    #[test]
    fn data_after_close_fails() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();

        // History: client sent a Close frame
        let close_evt = make_ws_event(conn, session, MessageDirection::Client, 8, 2);
        let history = ProtocolEventHistory::new(vec![close_evt]);

        // Now client sends a Text frame
        let text_evt = make_ws_event(conn, session, MessageDirection::Client, 1, 50);
        let result = rule.check_event(&text_evt, &history, &make_config());
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("after Close"));
    }

    #[test]
    fn data_from_other_direction_after_close_passes() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();

        // History: client sent a Close frame
        let close_evt = make_ws_event(conn, session, MessageDirection::Client, 8, 2);
        let history = ProtocolEventHistory::new(vec![close_evt]);

        // Server sends a Text frame (different direction — allowed during close handshake)
        let text_evt = make_ws_event(conn, session, MessageDirection::Server, 1, 50);
        let result = rule.check_event(&text_evt, &history, &make_config());
        assert!(result.is_none());
    }

    #[test]
    fn non_websocket_event_ignored() {
        let rule = StatefulWebsocketFrameOpcodeSequence;
        let evt = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::H3GoawayReceived {
                stream_id: None,
                direction: MessageDirection::Client,
            },
        };
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }
}
