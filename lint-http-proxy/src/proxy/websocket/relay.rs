// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The post-101 relay: a transparent byte pump per direction, each observed
//! by a passive frame scanner.
//!
//! The relay forwards the bytes it reads, unmodified — no re-masking, no
//! manufactured Pongs, no frames of its own — so what the origin receives is
//! byte-identical to what the client sent, and the capture is a record of
//! the wire rather than of the proxy. Invalid frames are recorded, linted,
//! and forwarded: RFC 6455 obliges the *receiving endpoint* to fail the
//! connection, and the EOF that follows is what ends the relay. Each
//! direction owns its observer outright; the session record is merged from
//! the two outcomes after both pumps finish, with no shared state to lock.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::proxy::pipeline::ProtocolEventPipeline;
use crate::websocket_session::{MessageDirection, WebSocketSession};

use super::observer::{DirectionObserver, DirectionOutcome};

/// One read in flight per direction; the read awaits the forward write, so
/// backpressure propagates through the relay instead of pooling in it.
const READ_BUF_BYTES: usize = 16 * 1024;

/// How long the surviving direction may keep draining after the other ends.
/// A conforming peer reaches its own EOF well inside this (the pump shuts
/// down the peer's write half, completing the close handshake); the grace
/// timer only guards a peer that ignores the FIN.
const DRAIN_GRACE: Duration = Duration::from_secs(30);

/// Relay bytes between client and server until both directions end, then
/// write the merged session record through the pipeline.
///
/// The extensions parameter is what the handshake settled, and it is passed
/// rather than re-read because the `101` this session came from is gone by
/// the time the relay runs — the same reason `tx_id` is passed. The pipeline
/// carries lint, the event store, and the capture writer alike.
pub(super) async fn relay_websocket(
    client_io: impl AsyncRead + AsyncWrite + Unpin + Send,
    server_io: impl AsyncRead + AsyncWrite + Unpin + Send,
    tx_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    extensions: crate::protocol_event::NegotiatedExtensions,
    pipeline: ProtocolEventPipeline,
    shutdown: CancellationToken,
) {
    // The session is created as the relay starts, so its timestamp is the
    // session's beginning — the fact replay uses as a frame's fallback time.
    let mut session = WebSocketSession::new(tx_id);
    let session_id = session.id;
    session.extensions = extensions.clone();
    let start = Instant::now();

    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);

    // Cancelled when the drain grace expires, so the surviving pump returns
    // its observer's outcome instead of being dropped mid-record.
    let drain_now = CancellationToken::new();

    let c2s = pump(
        client_read,
        server_write,
        DirectionObserver::new(
            MessageDirection::Client,
            connection_id,
            session_id,
            extensions.clone(),
            pipeline.clone(),
        ),
        shutdown.clone(),
        drain_now.clone(),
    );
    let s2c = pump(
        server_read,
        client_write,
        DirectionObserver::new(
            MessageDirection::Server,
            connection_id,
            session_id,
            extensions,
            pipeline.clone(),
        ),
        shutdown.clone(),
        drain_now.clone(),
    );
    tokio::pin!(c2s);
    tokio::pin!(s2c);

    // Whichever direction ends first, the other keeps draining under the
    // grace timer — frames already in flight on the surviving leg are still
    // relayed and recorded, where a plain select! would have dropped them.
    let (client_out, server_out) = tokio::select! {
        client_out = &mut c2s => {
            let server_out = finish_remaining(s2c, &drain_now).await;
            (client_out, server_out)
        }
        server_out = &mut s2c => {
            let client_out = finish_remaining(c2s, &drain_now).await;
            (client_out, server_out)
        }
    };

    session.duration_ms = start.elapsed().as_millis() as u64;
    session.messages = merge_frames(&client_out, &server_out);
    session.violations = client_out.violations;
    session
        .violations
        .extend(server_out.violations.iter().cloned());
    session.client_close_code = client_out.close_code;
    session.server_close_code = server_out.close_code;
    // The legacy single close code: the code of whichever direction's Close
    // frame came first in wire time, falling back to whichever direction has
    // one at all (a first Close with an empty payload carries no code).
    session.close_code = session
        .messages
        .iter()
        .find(|m| m.opcode == 8)
        .and_then(|m| match m.direction {
            MessageDirection::Client => client_out.close_code,
            MessageDirection::Server => server_out.close_code,
        })
        .or(client_out.close_code)
        .or(server_out.close_code);

    pipeline.commit_session(session).await;
}

/// Both directions' rows in wire order: merged by each frame's arrival time,
/// stably, so simultaneous stamps keep client-before-server order.
fn merge_frames(
    client_out: &DirectionOutcome,
    server_out: &DirectionOutcome,
) -> Vec<crate::websocket_session::WebSocketMessageInfo> {
    let mut frames = client_out.frames.clone();
    frames.extend(server_out.frames.iter().cloned());
    frames.sort_by_key(|f| f.timestamp);
    frames
}

/// Forward one direction: read a chunk, observe it, write it through. Ends
/// on EOF or io error from either side, on shutdown, or when the relay's
/// drain grace expires; the peer's write half is shut down on the way out so
/// the FIN (or TLS close_notify) propagates.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    mut observer: DirectionObserver,
    shutdown: CancellationToken,
    drain_now: CancellationToken,
) -> DirectionOutcome {
    let mut buf = [0u8; READ_BUF_BYTES];
    loop {
        let n = tokio::select! {
            r = read.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            _ = shutdown.cancelled() => break,
            _ = drain_now.cancelled() => break,
        };
        // Synchronous observation: nothing awaits between the read and the
        // forward write, so the record cannot reorder against the wire.
        observer.observe(&buf[..n]);
        if write.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    if observer.mid_frame() {
        debug!("websocket direction ended mid-frame");
    }
    let _ = write.shutdown().await;
    observer.into_outcome()
}

/// Await the still-running direction under the drain grace; when the grace
/// expires, cancel the drain token so the pump breaks out of its read and
/// returns its outcome — the observer's record survives either way.
async fn finish_remaining<F: Future<Output = DirectionOutcome>>(
    mut remaining: Pin<&mut F>,
    drain_now: &CancellationToken,
) -> DirectionOutcome {
    match tokio::time::timeout(DRAIN_GRACE, remaining.as_mut()).await {
        Ok(outcome) => outcome,
        Err(_) => {
            drain_now.cancel();
            remaining.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureWriter;
    use std::sync::Arc as StdArc;
    use uuid::Uuid;

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

        // Real endpoints on both ends of the transparent pipe.
        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;
        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Client sends a text message; the server receives it byte-identical
        // (the relay no longer re-masks, so the peer parses the client's own
        // masked frame).
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "hello".into(),
            ))
            .await?;
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
        let msg = client_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("world".into())
        );

        // Client closes; the server peer answers the close handshake.
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "done".into(),
                },
            )))
            .await?;
        let msg = server_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Close(_)
        ));
        server_ws.close(None).await.ok();
        client_ws.close(None).await.ok();

        // Drop both endpoints: EOF on both legs ends the relay.
        drop(client_ws);
        drop(server_ws);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        cw.flush().await?;

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
        // First message is the client text, with the real header bits: the
        // MASK bit a client must set, FIN, and a per-frame timestamp.
        assert_eq!(messages[0]["direction"].as_str(), Some("client"));
        assert_eq!(messages[0]["opcode"].as_u64(), Some(1));
        assert_eq!(messages[0]["masked"].as_bool(), Some(true));
        assert_eq!(messages[0]["fin"].as_bool(), Some(true));
        assert!(messages[0]["timestamp"].is_string());
        // Second is the server text, unmasked as a server must send.
        assert_eq!(messages[1]["direction"].as_str(), Some("server"));
        assert_eq!(messages[1]["opcode"].as_u64(), Some(1));
        assert_eq!(messages[1]["masked"].as_bool(), Some(false));
        // Both directions' Close frames are recorded, and the client's code
        // is readable per direction.
        assert_eq!(session["close_code"].as_u64(), Some(1000));
        assert_eq!(session["client_close_code"].as_u64(), Some(1000));

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
        // The server's Close carried 1000, and it came first, so the legacy
        // field holds it; the per-direction field says which side said it.
        assert_eq!(session["close_code"].as_u64(), Some(1000));
        assert_eq!(session["server_close_code"].as_u64(), Some(1000));
        let messages = session["messages"].as_array().unwrap();
        // Server text + server close + client close.
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

    /// The dependency's behavior, pinned — in the old direction: a reserved
    /// opcode never survived tungstenite's header parser, which is exactly
    /// why the relay stopped decoding through tungstenite. This keeps the
    /// rationale checkable against the real dependency; the relay-side proof
    /// that reserved opcodes now DO reach the capture lives in the scanner's
    /// and observer's own tests.
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
        assert_eq!(session["type"].as_str(), Some("websocket_session"));
        let messages = session["messages"].as_array().unwrap();
        // Binary both ways and the client ping, all with real header bits.
        assert!(messages.len() >= 3);
        let client_binary = messages
            .iter()
            .find(|m| m["opcode"].as_u64() == Some(2) && m["direction"] == "client")
            .expect("client binary recorded");
        assert_eq!(client_binary["masked"].as_bool(), Some(true));
        let ping = messages
            .iter()
            .find(|m| m["opcode"].as_u64() == Some(9))
            .expect("ping recorded");
        assert_eq!(ping["direction"].as_str(), Some("client"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }
}
