// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The post-101 frame relay: both upgraded legs wrapped in tungstenite
//! streams, each relayed message committed as a protocol event and recorded
//! into the session capture.

use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::proxy::pipeline::ProtocolEventPipeline;

/// Build the protocol event for a single relayed WebSocket frame, stamped with
/// its arrival time. Thin wrapper over the shared
/// [`WebSocketMessageInfo::frame_event`] mapping so live and offline replay
/// can't drift.
fn ws_frame_event(
    connection_id: uuid::Uuid,
    session_id: uuid::Uuid,
    info: &crate::websocket_session::WebSocketMessageInfo,
    extensions: &crate::protocol_event::NegotiatedExtensions,
) -> crate::protocol_event::ProtocolEvent {
    info.frame_event(chrono::Utc::now(), connection_id, session_id, extensions)
}

/// Relay WebSocket messages between client and server, recording each message
/// for capture. Uses tokio-tungstenite for proper RFC 6455 frame parsing.
///
/// The extensions parameter is what the handshake settled, and it is passed
/// rather than re-read because the `101` this session came from is gone by
/// the time the relay runs — the same reason `tx_id` is passed. The pipeline
/// carries lint, the event store, and the capture writer alike.
#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_websocket(
    client_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    server_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    tx_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    extensions: crate::protocol_event::NegotiatedExtensions,
    pipeline: ProtocolEventPipeline,
    shutdown: CancellationToken,
) {
    use crate::websocket_session::{MessageDirection, WebSocketMessageInfo, WebSocketSession};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    let client_ws =
        tokio_tungstenite::WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
    let server_ws =
        tokio_tungstenite::WebSocketStream::from_raw_socket(server_io, Role::Client, None).await;

    let (mut client_write, mut client_read) = client_ws.split();
    let (mut server_write, mut server_read) = server_ws.split();

    let session_id = uuid::Uuid::new_v4();
    let messages = Arc::new(tokio::sync::Mutex::new(Vec::<WebSocketMessageInfo>::new()));
    let violations = Arc::new(tokio::sync::Mutex::new(Vec::<crate::lint::Violation>::new()));
    let close_code = Arc::new(tokio::sync::Mutex::new(None::<u16>));
    let start = Instant::now();

    let ext_c2s = extensions.clone();
    let ext_s2c = extensions.clone();
    let msgs_c2s = messages.clone();
    let viols_c2s = violations.clone();
    let close_c2s = close_code.clone();
    let pipe_c2s = pipeline.clone();
    let c2s = async move {
        while let Some(result) = client_read.next().await {
            match result {
                Ok(msg) => {
                    let info = message_to_info(&msg, MessageDirection::Client);
                    if let tokio_tungstenite::tungstenite::Message::Close(Some(ref frame)) = msg {
                        let mut cc = close_c2s.lock().await;
                        if cc.is_none() {
                            *cc = Some(frame.code.into());
                        }
                    }
                    // Emit protocol event and lint it
                    let pe = ws_frame_event(connection_id, session_id, &info, &ext_c2s);
                    let v = pipe_c2s.commit(&pe);
                    if !v.is_empty() {
                        viols_c2s.lock().await.extend(v);
                    }

                    msgs_c2s.lock().await.push(info);
                    if server_write.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let msgs_s2c = messages.clone();
    let viols_s2c = violations.clone();
    let close_s2c = close_code.clone();
    let pipe_s2c = pipeline.clone();
    let s2c = async move {
        while let Some(result) = server_read.next().await {
            match result {
                Ok(msg) => {
                    let info = message_to_info(&msg, MessageDirection::Server);
                    if let tokio_tungstenite::tungstenite::Message::Close(Some(ref frame)) = msg {
                        let mut cc = close_s2c.lock().await;
                        if cc.is_none() {
                            *cc = Some(frame.code.into());
                        }
                    }
                    // Emit protocol event and lint it
                    let pe = ws_frame_event(connection_id, session_id, &info, &ext_s2c);
                    let v = pipe_s2c.commit(&pe);
                    if !v.is_empty() {
                        viols_s2c.lock().await.extend(v);
                    }

                    msgs_s2c.lock().await.push(info);
                    if client_write.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Run both directions concurrently; when either finishes, the session is
    // done. On shutdown, break promptly (dropping the IO halves closes both
    // sides) and still record the session below.
    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
        _ = shutdown.cancelled() => {},
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut session = WebSocketSession::new(tx_id);
    session.id = session_id;
    session.extensions = extensions;
    session.duration_ms = duration_ms;
    session.messages = match Arc::try_unwrap(messages) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().await.clone(),
    };
    session.close_code = match Arc::try_unwrap(close_code) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => *arc.lock().await,
    };
    session.violations = match Arc::try_unwrap(violations) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().await.clone(),
    };

    pipeline.commit_session(session).await;
}

fn message_to_info(
    msg: &tokio_tungstenite::tungstenite::Message,
    direction: crate::websocket_session::MessageDirection,
) -> crate::websocket_session::WebSocketMessageInfo {
    use crate::websocket_session::WebSocketMessageInfo;

    // These numbers are the wire format, not tungstenite's enum discriminants,
    // and this match is the only place the mapping is written down -- so it is
    // the opcode table, restated in Rust.
    //
    // Quoted as one extract rather than per arm, for a plain reason: "%x9 denotes
    // a ping" is eighteen characters and the extractor's floor is twenty. Ping and
    // pong cannot be quoted alone, so the list is quoted whole and each arm reads
    // its own line out of it.
    //
    // cite(RFC 6455 § 5.2): "%x0 denotes a continuation frame * %x1 denotes a text frame * %x2 denotes a binary frame * %x3-7 are reserved for further non-control frames * %x8 denotes a connection close * %x9 denotes a ping * %xA denotes a pong"
    let (opcode, payload_length, fin, rsv, masked) = match msg {
        // Assembled messages: tungstenite has already defragmented, so FIN is
        // implicitly true and the RSV and MASK bits are not available. `None`
        // is the honest record for the mask -- an assembled message has no
        // header, and *not recorded* is not *not masked*, which is the value
        // RFC 6455 § 5.1 makes a client's defect.
        tokio_tungstenite::tungstenite::Message::Text(s) => (1, s.len() as u64, true, 0u8, None),
        tokio_tungstenite::tungstenite::Message::Binary(b) => (2, b.len() as u64, true, 0, None),
        tokio_tungstenite::tungstenite::Message::Ping(b) => (9, b.len() as u64, true, 0, None),
        tokio_tungstenite::tungstenite::Message::Pong(b) => (10, b.len() as u64, true, 0, None),
        tokio_tungstenite::tungstenite::Message::Close(frame) => {
            let len = frame
                .as_ref()
                .map(|f| 2 + f.reason.len() as u64)
                .unwrap_or(0);
            (8, len, true, 0, None)
        }
        // Raw Frame variant: the header is there, so FIN, the RSV bits and the
        // MASK bit are all read from it. `is_masked` is the bit rather than the
        // key: § 5.2 defines the bit as *whether the payload data is masked*,
        // and a key is present exactly when it is set.
        tokio_tungstenite::tungstenite::Message::Frame(f) => {
            let hdr = f.header();
            let rsv_bits = ((hdr.rsv1 as u8) << 2) | ((hdr.rsv2 as u8) << 1) | (hdr.rsv3 as u8);
            (
                u8::from(hdr.opcode),
                f.payload().len() as u64,
                hdr.is_final,
                rsv_bits,
                Some(hdr.mask.is_some()),
            )
        }
    };
    WebSocketMessageInfo {
        direction,
        opcode,
        payload_length,
        fin,
        rsv,
        masked,
        timestamp: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureWriter;
    use std::sync::Arc as StdArc;
    use uuid::Uuid;

    /// The MASK bit reaches the event only from the raw frame path, and an
    /// assembled message records `None` rather than `false`.
    ///
    /// The distinction is the whole of `websocket_frame_masking`'s
    /// decline: `false` is RFC 6455 § 5.1's finding against a client, and an
    /// assembled `Text` has no header to have read it from.
    #[test]
    fn message_to_info_records_the_mask_bit_only_where_a_header_carried_one() {
        use crate::websocket_session::MessageDirection;
        use tokio_tungstenite::tungstenite::protocol::frame::{
            coding::{Data, OpCode},
            Frame, FrameHeader,
        };
        use tokio_tungstenite::tungstenite::Message;

        let assembled = message_to_info(&Message::text("hi"), MessageDirection::Client);
        assert_eq!(assembled.masked, None, "an assembled message has no header");

        let header = FrameHeader {
            is_final: true,
            opcode: OpCode::Data(Data::Text),
            mask: Some([1, 2, 3, 4]),
            ..Default::default()
        };
        let masked = message_to_info(
            &Message::Frame(Frame::from_payload(header, b"hi"[..].into())),
            MessageDirection::Client,
        );
        assert_eq!(masked.masked, Some(true));

        let header = FrameHeader {
            is_final: true,
            opcode: OpCode::Data(Data::Text),
            mask: None,
            ..Default::default()
        };
        let unmasked = message_to_info(
            &Message::Frame(Frame::from_payload(header, b"hi"[..].into())),
            MessageDirection::Client,
        );
        assert_eq!(unmasked.masked, Some(false));
    }

    fn test_pe_pipeline(captures: &CaptureWriter) -> ProtocolEventPipeline {
        let cfg = crate::config::Config::default();
        let engine = StdArc::new(crate::engine::PreparedEngine::new(&cfg).unwrap());
        ProtocolEventPipeline::new(
            engine,
            StdArc::new(crate::protocol_event_store::ProtocolEventStore::new(
                300, 100,
            )),
            captures.clone(),
        )
    }

    #[test]
    fn message_to_info_text() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Text("hello".into());
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 1);
        assert_eq!(info.payload_length, 5);
        assert_eq!(info.direction, MessageDirection::Client);
    }

    #[test]
    fn message_to_info_binary() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Binary(vec![1, 2, 3].into());
        let info = message_to_info(&msg, MessageDirection::Server);
        assert_eq!(info.opcode, 2);
        assert_eq!(info.payload_length, 3);
        assert_eq!(info.direction, MessageDirection::Server);
    }

    #[test]
    fn message_to_info_ping_pong() {
        use crate::websocket_session::MessageDirection;
        let ping = tokio_tungstenite::tungstenite::Message::Ping(vec![0; 4].into());
        let info = message_to_info(&ping, MessageDirection::Client);
        assert_eq!(info.opcode, 9);
        assert_eq!(info.payload_length, 4);

        let pong = tokio_tungstenite::tungstenite::Message::Pong(vec![0; 2].into());
        let info = message_to_info(&pong, MessageDirection::Server);
        assert_eq!(info.opcode, 10);
        assert_eq!(info.payload_length, 2);
    }

    #[test]
    fn message_to_info_close_with_frame() {
        use crate::websocket_session::MessageDirection;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        let msg = tokio_tungstenite::tungstenite::Message::Close(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "bye".into(),
        }));
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 8);
        // 2 bytes for code + 3 bytes for "bye"
        assert_eq!(info.payload_length, 5);
    }

    #[test]
    fn message_to_info_close_without_frame() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Close(None);
        let info = message_to_info(&msg, MessageDirection::Server);
        assert_eq!(info.opcode, 8);
        assert_eq!(info.payload_length, 0);
    }

    #[tokio::test]
    async fn relay_websocket_relays_messages_and_captures_session() -> anyhow::Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        // Create two duplex pairs to simulate client<->proxy and proxy<->server
        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp = std::env::temp_dir().join(format!("lint_ws_relay_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        // Spawn the relay
        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                uuid::Uuid::new_v4(),
                crate::protocol_event::NegotiatedExtensions::NoneAccepted,
                test_pe_pipeline(&cw_clone),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        });

        // Client side: wrap in WebSocket (client role)
        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        // Server side: wrap in WebSocket (server role)
        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Client sends a text message
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "hello".into(),
            ))
            .await?;

        // Server should receive it
        let msg = server_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("hello".into())
        );

        // Server sends a response
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "world".into(),
            ))
            .await?;

        // Client should receive it
        let msg = client_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("world".into())
        );

        // Client sends close
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "done".into(),
                },
            )))
            .await?;

        // Server receives close and sends close back
        let msg = server_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Close(_)
        ));
        server_ws.close(None).await.ok();

        // Close client side
        client_ws.close(None).await.ok();

        // Wait for relay to finish
        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        // Flush captures
        cw.flush().await?;

        // Read the capture file and verify the WebSocket session was written
        let content = tokio::fs::read_to_string(&p).await?;
        assert!(!content.is_empty(), "capture file should not be empty");
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));
        assert_eq!(
            session["transaction_id"].as_str(),
            Some(tx_id.to_string().as_str())
        );
        let messages = session["messages"].as_array().unwrap();
        assert!(messages.len() >= 2, "should have at least 2 messages");
        // First message should be client text
        assert_eq!(messages[0]["direction"].as_str(), Some("client"));
        assert_eq!(messages[0]["opcode"].as_u64(), Some(1));
        // Second message should be server text
        assert_eq!(messages[1]["direction"].as_str(), Some("server"));
        assert_eq!(messages[1]["opcode"].as_u64(), Some(1));
        // Should have a close code
        assert_eq!(session["close_code"].as_u64(), Some(1000));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_server_initiated_close() -> anyhow::Result<()> {
        // Test the s2c direction: server sends close first
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp = std::env::temp_dir().join(format!("lint_ws_s2c_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                uuid::Uuid::new_v4(),
                crate::protocol_event::NegotiatedExtensions::NoneAccepted,
                test_pe_pipeline(&cw_clone),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        });

        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Server sends a message first
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "server-msg".into(),
            ))
            .await?;
        let msg = client_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("server-msg".into())
        );

        // Server initiates close
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "server-done".into(),
                },
            )))
            .await?;

        // Client receives close and responds
        let msg = client_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Close(_)
        ));
        // Send close response then drop to end the c2s stream
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .ok();
        drop(client_ws);
        drop(server_ws);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        cw.flush().await?;

        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));
        // Close was from server direction
        assert_eq!(session["close_code"].as_u64(), Some(1000));
        let messages = session["messages"].as_array().unwrap();
        // Should have server text + server close + possibly client close
        assert!(messages.len() >= 2);

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_abrupt_disconnect() -> anyhow::Result<()> {
        // Test error path: client disconnects abruptly
        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_abrupt_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                uuid::Uuid::new_v4(),
                crate::protocol_event::NegotiatedExtensions::NoneAccepted,
                test_pe_pipeline(&cw_clone),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        });

        // Drop client and server immediately to simulate abrupt disconnect
        drop(client_side);
        drop(server_side);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        cw.flush().await?;

        // Should still write a session record (with empty messages)
        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_closes_on_shutdown() -> anyhow::Result<()> {
        // Both peers stay connected (no frames, no close), so the relay only
        // ends when the shutdown token is cancelled — proving it observes it
        // and closes gracefully rather than lingering to the drain timeout.
        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);
        // Keep the peer ends alive so the relay's reads stay pending (not EOF).
        let _client_side = client_side;
        let _server_side = server_side;

        let tx_id = Uuid::new_v4();
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_shutdown_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let shutdown = tokio_util::sync::CancellationToken::new();
        let cw_clone = cw.clone();
        let shutdown_relay = shutdown.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                uuid::Uuid::new_v4(),
                crate::protocol_event::NegotiatedExtensions::NoneAccepted,
                test_pe_pipeline(&cw_clone),
                shutdown_relay,
            )
            .await;
        });

        // Let the relay start and block on its idle reads, then signal shutdown.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not stop on shutdown")
            .expect("relay panicked");

        // The session is still recorded on the shutdown path.
        cw.flush().await?;
        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[test]
    fn message_to_info_frame_variant() {
        use crate::websocket_session::MessageDirection;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::OpCode;
        use tokio_tungstenite::tungstenite::protocol::frame::{Frame, FrameHeader};
        let header = FrameHeader {
            is_final: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Data(
                tokio_tungstenite::tungstenite::protocol::frame::coding::Data::Text,
            ),
            mask: None,
        };
        let frame = Frame::from_payload(header, vec![b'h', b'i'].into());
        let msg = tokio_tungstenite::tungstenite::Message::Frame(frame);
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 1); // Text opcode
        assert_eq!(info.payload_length, 2);
    }

    /// The dependency on the capture path, pinned: a reserved opcode never
    /// reaches `message_to_info`, because the frame reader refuses it in the
    /// header parser before any of the rest of the header is used. Two ranges,
    /// and everything the document defines still parses.
    ///
    /// `websocket_frame_opcode_sequence` reports reserved opcodes, and
    /// this is why its `description()` says those findings arrive through
    /// `lint` over a capture file some other tool wrote rather than off this
    /// proxy's own relay. When this test fails, that paragraph is what has gone
    /// stale.
    #[test]
    fn the_frame_reader_refuses_a_reserved_opcode_before_the_capture_path() {
        use std::io::Cursor;
        use tokio_tungstenite::tungstenite::protocol::frame::FrameHeader;

        // First byte: FIN set, no reserved bits, opcode in the low nibble.
        // Second byte: unmasked, payload length 0.
        for reserved in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            let head = [0x80 | reserved, 0x00];
            assert!(
                FrameHeader::parse(&mut Cursor::new(&head)).is_err(),
                "opcode {reserved:#x} must not reach a capture"
            );
        }
        for defined in [0x0u8, 0x1, 0x2, 0x8, 0x9, 0xA] {
            let head = [0x80 | defined, 0x00];
            let parsed = FrameHeader::parse(&mut Cursor::new(&head))
                .expect("a defined opcode parses")
                .expect("the two-byte head is complete");
            assert_eq!(u8::from(parsed.0.opcode), defined);
        }
    }

    #[tokio::test]
    async fn relay_websocket_binary_and_ping_messages() -> anyhow::Result<()> {
        // Test relay with binary and ping/pong messages to cover more message_to_info paths
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_binary_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                uuid::Uuid::new_v4(),
                crate::protocol_event::NegotiatedExtensions::NoneAccepted,
                test_pe_pipeline(&cw_clone),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        });

        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Client sends binary
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![1, 2, 3].into(),
            ))
            .await?;
        let msg = server_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Binary(_)
        ));

        // Server sends binary back
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![4, 5, 6].into(),
            ))
            .await?;
        let msg = client_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Binary(_)
        ));

        // Client sends ping
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Ping(
                vec![7, 8].into(),
            ))
            .await?;

        // Server receives ping (may receive pong auto-response)
        let msg = server_ws.next().await.unwrap()?;
        assert!(
            matches!(msg, tokio_tungstenite::tungstenite::Message::Ping(_))
                || matches!(msg, tokio_tungstenite::tungstenite::Message::Pong(_))
        );

        // Close
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .ok();
        drop(client_ws);
        drop(server_ws);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        cw.flush().await?;

        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        let messages = session["messages"].as_array().unwrap();
        // Should have binary c2s, binary s2c, ping, and close messages
        assert!(messages.len() >= 3);

        // Verify binary opcode (2) appears
        assert!(messages.iter().any(|m| m["opcode"].as_u64() == Some(2)));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }
}
