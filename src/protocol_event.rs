// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Protocol-level event model for sub-transaction analysis.
//!
//! While [`HttpTransaction`] captures complete request/response pairs, some
//! lint rules need visibility into frame-level and transport-level events that
//! occur outside or below the HTTP message abstraction: WebSocket frames,
//! HTTP/3 control frames, QUIC transport parameters, etc.
//!
//! `ProtocolEvent` represents a single observable event on a connection.
//! Events are stored in [`ProtocolEventStore`](crate::protocol_event_store)
//! and routed to [`ProtocolRule`](crate::rules::ProtocolRule) implementations
//! via [`lint_protocol_event`](crate::lint_protocol::lint_protocol_event).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// A single protocol-level event observed on a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolEvent {
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Connection this event belongs to (correlates with
    /// `HttpTransaction::connection_id`).
    pub connection_id: Uuid,
    /// The event payload.
    pub kind: ProtocolEventKind,
}

/// Discriminated payload for protocol events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolEventKind {
    // ── WebSocket ──────────────────────────────────────────────────────
    /// A single WebSocket message observed during relay.
    WebSocketFrame {
        /// Session ID linking back to the `WebSocketSession`.
        session_id: Uuid,
        direction: crate::websocket_session::MessageDirection,
        /// FIN bit.  `true` for assembled messages (tungstenite default);
        /// raw `Frame` variant exposes the actual bit.
        fin: bool,
        /// RFC 6455 opcode (1=Text, 2=Binary, 8=Close, 9=Ping, 10=Pong).
        opcode: u8,
        /// RSV bits packed into the low 3 bits (RSV1=bit 2, RSV2=bit 1,
        /// RSV3=bit 0).  Zero when unavailable.
        rsv: u8,
        /// Payload length in bytes.
        payload_length: u64,
    },

    // ── HTTP/3 connection-level ────────────────────────────────────────
    /// GOAWAY received (connection shutting down gracefully).
    H3GoawayReceived {
        /// Stream ID from the GOAWAY frame, if the h3 crate exposes it.
        stream_id: Option<u64>,
    },

    /// A new HTTP/3 request stream was accepted.
    H3StreamOpened {
        /// Proxy-assigned stream sequence number (not the wire stream ID
        /// until frame-level wrapping is available).
        stream_id: u64,
    },

    /// An HTTP/3 request stream completed processing.
    H3StreamClosed { stream_id: u64 },

    /// SETTINGS frame received on the control stream.
    H3SettingsReceived {
        /// (setting_id, value) pairs.
        settings: Vec<(u64, u64)>,
    },

    /// MAX_PUSH_ID frame received.
    H3MaxPushId { push_id: u64 },

    // ── QUIC transport-level ───────────────────────────────────────────
    /// Negotiated QUIC transport parameters after handshake.
    QuicTransportParams { params: QuicTransportParameters },

    /// QUIC flow-control window update.
    QuicFlowControlUpdate {
        /// `None` for connection-level; `Some(id)` for stream-level.
        stream_id: Option<u64>,
        window: u64,
    },

    /// Connection migrated to a new path.
    QuicConnectionMigration {
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    },

    /// QUIC version negotiation event.
    QuicVersionNegotiation {
        client_version: u32,
        server_versions: Vec<u32>,
    },
}

/// Subset of QUIC transport parameters relevant to HTTP/3 linting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicTransportParameters {
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub max_idle_timeout_ms: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
}

/// Pre-queried protocol event history passed to protocol rules.
///
/// Contains zero or more previous events for the same connection,
/// ordered **newest first**.  Mirrors [`TransactionHistory`] for the
/// protocol event pipeline.
#[derive(Debug, Clone)]
pub struct ProtocolEventHistory {
    entries: Vec<ProtocolEvent>,
}

impl ProtocolEventHistory {
    /// Create an empty history.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create a history from a pre-sorted (newest-first) list.
    pub fn new(entries: Vec<ProtocolEvent>) -> Self {
        #[cfg(debug_assertions)]
        {
            for pair in entries.windows(2) {
                if let [ref first, ref second] = pair {
                    debug_assert!(
                        first.timestamp >= second.timestamp,
                        "ProtocolEventHistory::new must be given newest-first entries"
                    );
                }
            }
        }
        Self { entries }
    }

    /// Most recent previous event, if any.
    pub fn previous(&self) -> Option<&ProtocolEvent> {
        self.entries.first()
    }

    /// Iterate over all entries, newest first.
    pub fn iter(&self) -> impl Iterator<Item = &ProtocolEvent> {
        self.entries.iter()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: ProtocolEventKind) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind,
        }
    }

    #[test]
    fn empty_history() {
        let h = ProtocolEventHistory::empty();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.previous().is_none());
        assert_eq!(h.iter().count(), 0);
    }

    #[test]
    fn history_with_entries() {
        let conn = Uuid::new_v4();
        let e1 = ProtocolEvent {
            timestamp: Utc::now() + chrono::Duration::seconds(1),
            connection_id: conn,
            kind: ProtocolEventKind::H3GoawayReceived { stream_id: None },
        };
        let e2 = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: conn,
            kind: ProtocolEventKind::H3StreamOpened { stream_id: 0 },
        };
        let h = ProtocolEventHistory::new(vec![e1.clone(), e2]);
        assert_eq!(h.len(), 2);
        assert!(!h.is_empty());
        assert_eq!(h.previous().unwrap().connection_id, e1.connection_id);
    }

    #[test]
    fn serde_roundtrip_websocket_frame() {
        let evt = make_event(ProtocolEventKind::WebSocketFrame {
            session_id: Uuid::new_v4(),
            direction: crate::websocket_session::MessageDirection::Client,
            fin: true,
            opcode: 1,
            rsv: 0,
            payload_length: 42,
        });
        let json = serde_json::to_string(&evt).unwrap();
        let deserialized: ProtocolEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connection_id, evt.connection_id);
    }

    #[test]
    fn serde_roundtrip_h3_goaway() {
        let evt = make_event(ProtocolEventKind::H3GoawayReceived { stream_id: Some(4) });
        let json = serde_json::to_string(&evt).unwrap();
        let deserialized: ProtocolEvent = serde_json::from_str(&json).unwrap();
        if let ProtocolEventKind::H3GoawayReceived { stream_id } = deserialized.kind {
            assert_eq!(stream_id, Some(4));
        } else {
            panic!("unexpected variant");
        }
    }
}
