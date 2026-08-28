// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Protocol-level event model for sub-transaction analysis.
//!
//! While [`HttpTransaction`](crate::http_transaction::HttpTransaction) captures
//! complete request/response pairs, some lint rules need visibility into
//! frame-level and transport-level events that occur outside or below the HTTP
//! message abstraction: WebSocket frames, HTTP/3 control frames, QUIC transport
//! parameters, etc.
//!
//! `ProtocolEvent` represents a single observable event on a connection.
//! Events are stored in [`ProtocolEventStore`](crate::protocol_event_store)
//! and routed to `ProtocolRule` implementations via `lint_protocol_event` —
//! both in the `lint-http-rules` crate, which depends on this one and not the
//! reverse, so they are named here rather than linked.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// Direction of a message relative to the proxy: which peer sent it. For a
/// WebSocket frame this is the message direction; for an HTTP/3 or QUIC event it
/// identifies the *sender's role on the observed connection* — `Client` for a
/// frame the downstream client sent (or the proxy's own client-facing leg),
/// `Server` for a frame an upstream origin server sent (the upstream leg). This
/// is what lets a rule tell an origin-sent MAX_PUSH_ID (a violation, RFC 9114
/// §7.2.7) from a client-sent one.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    /// Client to server.
    Client,
    /// Server to client.
    Server,
}

/// Default direction for H3/QUIC events deserialized from records written
/// before the field existed: the proxy only observed the client-facing leg
/// then, so those events were client-sent.
fn default_direction_client() -> MessageDirection {
    MessageDirection::Client
}

/// What the opening handshake of a WebSocket session negotiated, carried on
/// every frame of that session.
///
/// **Three states, because two of them are the same word in English and not the
/// same fact.** A frame-level rule asking about RFC 6455's reserved bits and
/// reserved opcodes needs to know whether *any* extension was negotiated, since
/// the specification hands both to extensions and requires the negotiation to
/// happen in the opening handshake — which is an HTTP exchange a
/// `ProtocolRule` never sees. So the answer
/// travels with the frame, and *"the server accepted no extension"* is a
/// different record from *"this capture does not say"*: the first licenses a
/// finding, and the second is why [`Unrecorded`](Self::Unrecorded) is the
/// serde default. Every event written before this field existed deserializes to
/// it, and so does every capture written by something other than this proxy.
///
/// The value is repeated per frame rather than held once per session on
/// purpose. A rule decides per frame, and the alternative — a session-opened
/// event read out of the history — is bounded by `max_protocol_event_history`,
/// so a long session would silently stop answering the question.
///
/// **The response's field is the whole of the agreement**, which is what makes
/// a missing one an answer rather than a silence: a client's own
/// `Sec-WebSocket-Extensions` is an offer it may not act on, and the sentence
/// below says the server's list is what is in use.
///
/// cite(RFC 6455 § 5.8): "The endpoints of a connection MUST negotiate the use of any extensions during the opening handshake."
/// cite(RFC 6455 § 9.1): "The extensions listed by the server in response represent the extensions actually in use for the connection."
/// cite(RFC 6455 § 9.1): "Note that the client is only offering to use any advertised extensions and MUST NOT use them unless the server indicates that it wishes to use the extension."
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NegotiatedExtensions {
    /// The capture does not record the handshake this session was opened by.
    #[default]
    Unrecorded,
    /// The `101` carried no `Sec-WebSocket-Extensions` field, so the server
    /// accepted none.
    NoneAccepted,
    /// The `Sec-WebSocket-Extensions` value the `101` carried, as the server
    /// wrote it.
    Accepted(String),
}

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
        direction: MessageDirection,
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
        /// What the `101` that opened this session accepted, so that a rule
        /// reading the bits and opcodes RFC 6455 reserves for extensions can
        /// tell an extension's frame from a defect. See
        /// [`NegotiatedExtensions`] for why the absent case is three states
        /// and not two.
        #[serde(default)]
        extensions: NegotiatedExtensions,
        /// The MASK bit, when the record holds one. `None` is *not recorded* --
        /// an assembled message has no frame header to read it from, and every
        /// event written before this field existed reads back as it -- and
        /// never *not masked*, which is the value RFC 6455 § 5.1 makes a
        /// client's defect. Only the raw frame path can answer this, so a rule
        /// asking it must treat the absent case as no evidence.
        #[serde(default)]
        masked: Option<bool>,
    },

    // ── HTTP/3 connection-level ────────────────────────────────────────
    /// GOAWAY received (connection shutting down gracefully).
    H3GoawayReceived {
        /// Stream ID from the GOAWAY frame, if the h3 crate exposes it.
        stream_id: Option<u64>,
        /// Which peer sent the GOAWAY (a server GOAWAY carries a request stream
        /// ID; a client GOAWAY carries a push ID — RFC 9114 §5.2).
        #[serde(default = "default_direction_client")]
        direction: MessageDirection,
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
        /// Which peer sent the SETTINGS (each peer sends its own on its control
        /// stream, so this scopes duplicate-frame checks per direction).
        #[serde(default = "default_direction_client")]
        direction: MessageDirection,
    },

    /// MAX_PUSH_ID frame received.
    H3MaxPushId {
        push_id: u64,
        /// Which peer sent it — a server MUST NOT send MAX_PUSH_ID (RFC 9114
        /// §7.2.7), so `Server` here is a violation.
        #[serde(default = "default_direction_client")]
        direction: MessageDirection,
    },

    // ── QUIC transport-level ───────────────────────────────────────────
    /// Negotiated QUIC transport parameters after handshake.
    QuicTransportParams {
        params: QuicTransportParameters,
        /// Whose parameters these are: `Client` for the proxy's own client-facing
        /// advertisement, `Server` for an upstream origin's real parameters.
        #[serde(default = "default_direction_client")]
        direction: MessageDirection,
    },

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
/// ordered **newest first**.  Mirrors
/// [`TransactionHistory`](crate::transaction_history::TransactionHistory) for
/// the protocol event pipeline.
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
            kind: ProtocolEventKind::H3GoawayReceived {
                stream_id: None,
                direction: MessageDirection::Client,
            },
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
            direction: MessageDirection::Client,
            fin: true,
            opcode: 1,
            rsv: 0,
            extensions: NegotiatedExtensions::Unrecorded,
            masked: None,
            payload_length: 42,
        });
        let json = serde_json::to_string(&evt).unwrap();
        let deserialized: ProtocolEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connection_id, evt.connection_id);
    }

    #[test]
    fn serde_roundtrip_h3_goaway() {
        let evt = make_event(ProtocolEventKind::H3GoawayReceived {
            stream_id: Some(4),
            direction: MessageDirection::Client,
        });
        let json = serde_json::to_string(&evt).unwrap();
        let deserialized: ProtocolEvent = serde_json::from_str(&json).unwrap();
        if let ProtocolEventKind::H3GoawayReceived { stream_id, .. } = deserialized.kind {
            assert_eq!(stream_id, Some(4));
        } else {
            panic!("unexpected variant");
        }
    }
}
