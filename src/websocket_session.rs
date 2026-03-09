// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket session capture data model.
//!
//! Represents a WebSocket session as a sequence of messages exchanged after
//! a 101 Switching Protocols upgrade. Each session is linked to the HTTP
//! transaction that initiated the upgrade via `transaction_id`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Direction of a WebSocket message relative to the proxy.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    /// Client to server.
    Client,
    /// Server to client.
    Server,
}

/// A single WebSocket message observed during relay.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebSocketMessageInfo {
    pub direction: MessageDirection,
    /// RFC 6455 opcode: 1=Text, 2=Binary, 8=Close, 9=Ping, 10=Pong.
    pub opcode: u8,
    /// Payload length in bytes.
    pub payload_length: u64,
    /// FIN bit.  `true` for assembled messages (tungstenite default);
    /// the raw `Frame` variant exposes the actual bit.
    #[serde(default = "default_fin")]
    pub fin: bool,
    /// RSV bits packed into the low 3 bits (RSV1=bit 2, RSV2=bit 1,
    /// RSV3=bit 0).  Zero when unavailable.
    #[serde(default)]
    pub rsv: u8,
}

fn default_fin() -> bool {
    true
}

/// A captured WebSocket session linking back to the 101 upgrade transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSocketSession {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub messages: Vec<WebSocketMessageInfo>,
    /// Close status code from the first Close frame, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_code: Option<u16>,
    /// Protocol-level violations detected during the session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<crate::lint::Violation>,
    /// Discriminator for JSONL record types.
    #[serde(rename = "type")]
    pub record_type: String,
}

impl WebSocketSession {
    pub fn new(transaction_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            transaction_id,
            timestamp: Utc::now(),
            duration_ms: 0,
            messages: Vec::new(),
            close_code: None,
            violations: Vec::new(),
            record_type: "websocket_session".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let tx_id = Uuid::new_v4();
        let mut session = WebSocketSession::new(tx_id);
        session.messages.push(WebSocketMessageInfo {
            direction: MessageDirection::Client,
            opcode: 1,
            payload_length: 13,
            fin: true,
            rsv: 0,
        });
        session.messages.push(WebSocketMessageInfo {
            direction: MessageDirection::Server,
            opcode: 1,
            payload_length: 42,
            fin: true,
            rsv: 0,
        });
        session.messages.push(WebSocketMessageInfo {
            direction: MessageDirection::Client,
            opcode: 8,
            payload_length: 2,
            fin: true,
            rsv: 0,
        });
        session.close_code = Some(1000);
        session.duration_ms = 150;

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: WebSocketSession = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, session.id);
        assert_eq!(deserialized.transaction_id, tx_id);
        assert_eq!(deserialized.messages.len(), 3);
        assert_eq!(deserialized.messages[0].direction, MessageDirection::Client);
        assert_eq!(deserialized.messages[0].opcode, 1);
        assert_eq!(deserialized.close_code, Some(1000));
        assert_eq!(deserialized.record_type, "websocket_session");
    }

    #[test]
    fn record_type_serializes_as_type() {
        let session = WebSocketSession::new(Uuid::new_v4());
        let v: serde_json::Value = serde_json::to_value(&session).unwrap();
        assert_eq!(v["type"].as_str(), Some("websocket_session"));
        assert!(v.get("record_type").is_none());
    }

    #[test]
    fn close_code_omitted_when_none() {
        let session = WebSocketSession::new(Uuid::new_v4());
        let json = serde_json::to_string(&session).unwrap();
        assert!(!json.contains("close_code"));
    }

    #[test]
    fn direction_serializes_lowercase() {
        let msg = WebSocketMessageInfo {
            direction: MessageDirection::Server,
            opcode: 2,
            payload_length: 100,
            fin: true,
            rsv: 0,
        };
        let v: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["direction"].as_str(), Some("server"));
    }
}
