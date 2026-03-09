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
use crate::rules::{ProtocolRule, RuleConfig};

pub struct StatefulWebsocketFrameOpcodeSequence;

impl ProtocolRule for StatefulWebsocketFrameOpcodeSequence {
    type Config = RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_websocket_frame_opcode_sequence"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use crate::websocket_session::MessageDirection;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_config() -> RuleConfig {
        RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        }
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
            kind: ProtocolEventKind::H3GoawayReceived { stream_id: None },
        };
        let result = rule.check_event(&evt, &ProtocolEventHistory::empty(), &make_config());
        assert!(result.is_none());
    }
}
