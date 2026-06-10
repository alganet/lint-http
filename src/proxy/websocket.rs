// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket upgrade handshake and bidirectional frame relay.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::error;

use crate::capture::CaptureWriter;

use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::pipeline::ProtocolEventPipeline;
use super::Shared;

/// Check if a request is a WebSocket upgrade request.
///
/// RFC 6455 §4.1: a WebSocket handshake requires `Connection: Upgrade` (as a
/// distinct token, possibly alongside others) and `Upgrade: websocket`.
pub(super) fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let connection_tokens = parse_connection_tokens(req.headers().get(hyper::header::CONNECTION));
    let has_upgrade = connection_tokens.contains("upgrade");
    let is_websocket = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    has_upgrade && is_websocket
}

/// Handle a WebSocket upgrade request: connect directly to upstream, relay
/// frames via tokio-tungstenite, and capture the session.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_websocket_upgrade(
    upstream_req: Request<Full<Bytes>>,
    client_on_upgrade: hyper::upgrade::OnUpgrade,
    uri: &Uri,
    scheme: &hyper::http::uri::Scheme,
    started: &Instant,
    client_id: &crate::state::ClientIdentifier,
    method: &Method,
    uri_str: &str,
    req_headers: &hyper::HeaderMap,
    req_version: &str,
    body_bytes: Bytes,
    req_trailers: Option<hyper::HeaderMap>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    // Connect directly to upstream with upgrade support
    let (mut sender, _conn_handle) = match connect_upstream_for_upgrade(uri, scheme).await {
        Ok(s) => s,
        Err(e) => {
            error!("websocket upstream connect error: {}", e);
            let body = Full::new(Bytes::from(format!("websocket upstream error: {}", e))).boxed();
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            return Ok(resp);
        }
    };

    // Send the upgrade request to the upstream server
    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("websocket upstream request error: {}", e);
            let body = Full::new(Bytes::from(format!("websocket upstream error: {}", e))).boxed();
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            return Ok(resp);
        }
    };

    let status = upstream_resp.status().as_u16();
    let headers = upstream_resp.headers().clone();
    let resp_ver = format_http_version(upstream_resp.version());
    let duration = started.elapsed().as_millis() as u64;

    // Record the HTTP transaction (the 101 handshake)
    let mut tx = crate::http_transaction::HttpTransaction::new(
        client_id.clone(),
        method.as_str().to_string(),
        uri_str.to_string(),
    );
    tx.request.headers = req_headers.clone();
    tx.request.version = req_version.to_string();
    tx.request.body_length = Some(body_bytes.len() as u64);
    tx.request.trailers = req_trailers;
    tx.request_body = Some(body_bytes);
    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: headers.clone(),
        body_length: Some(0),
        trailers: None,
    });
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };
    tx.connection_id = Some(conn_metadata.id);
    tx.sequence_number = Some(conn_metadata.next_sequence_number());
    if status == 101 {
        tx.was_upgraded = true;
        tx.upgrade_protocol = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
    }

    let tx_id = tx.id;
    shared.pipeline().commit(tx).await;

    if status == 101 {
        // Extract the server-side upgraded IO
        let server_upgraded = hyper::upgrade::on(&mut upstream_resp);

        // Build the 101 response to send back to the client.
        // Forward ALL headers including upgrade-related ones (Connection, Upgrade,
        // Sec-WebSocket-Accept) — do NOT strip hop-by-hop headers for 101.
        let mut resp_builder = Response::builder().status(101);
        for (name, value) in headers.iter() {
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(Full::new(Bytes::new()).boxed())
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()));

        // Spawn background relay task
        let captures_clone = shared.captures.clone();
        let connection_id = conn_metadata.id;
        let pe_pipeline = shared.protocol_event_pipeline();
        tokio::spawn(async move {
            // Wait for both sides to complete the upgrade
            let (client_io, server_io) = match tokio::try_join!(client_on_upgrade, server_upgraded)
            {
                Ok((c, s)) => (c, s),
                Err(e) => {
                    error!("websocket upgrade failed: {}", e);
                    return;
                }
            };

            relay_websocket(
                TokioIo::new(client_io),
                TokioIo::new(server_io),
                tx_id,
                captures_clone,
                connection_id,
                pe_pipeline,
            )
            .await;
        });

        Ok(resp)
    } else {
        // Upstream did not accept the upgrade; return the response normally
        let resp_body = match upstream_resp.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => Bytes::new(),
        };

        let mut resp_builder = Response::builder().status(status);
        let connection_hop_headers =
            parse_connection_tokens(headers.get(hyper::header::CONNECTION));
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_ascii_lowercase();
            if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
                continue;
            }
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(Full::new(resp_body).boxed())
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()));

        Ok(resp)
    }
}

/// Open a direct TCP (or TLS) connection to the upstream host and perform
/// an HTTP/1.1 handshake with upgrade support.
///
/// `fallback_scheme` is used only when the URI itself has no scheme set
/// (origin-form requests).  An absolute-form URI's own scheme always wins,
/// so the scheme used for TLS and the default port can never disagree with
/// what's in the URI.
async fn connect_upstream_for_upgrade(
    uri: &Uri,
    fallback_scheme: &hyper::http::uri::Scheme,
) -> anyhow::Result<(
    hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
)> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in URI"))?;
    let scheme = uri.scheme().unwrap_or(fallback_scheme);
    let is_https = *scheme == hyper::http::uri::Scheme::HTTPS;
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

    let tcp = tokio::net::TcpStream::connect((host, port)).await?;

    if is_https {
        let cert_result = rustls_native_certs::load_native_certs();
        if !cert_result.errors.is_empty() {
            tracing::warn!(
                errors = ?cert_result.errors,
                "encountered errors loading platform certificates"
            );
        }
        if cert_result.certs.is_empty() {
            return Err(anyhow::anyhow!(
                "failed to load any platform certificates: {:?}",
                cert_result.errors
            ));
        }
        let mut root_store = rustls::RootCertStore::empty();
        for cert in cert_result.certs {
            root_store.add(cert).ok();
        }
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(server_name, tcp).await?;

        let (sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
        let handle = tokio::spawn(conn.with_upgrades());
        Ok((sender, handle))
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        let handle = tokio::spawn(conn.with_upgrades());
        Ok((sender, handle))
    }
}

/// Build the protocol event for a single relayed WebSocket frame.
fn ws_frame_event(
    connection_id: uuid::Uuid,
    session_id: uuid::Uuid,
    info: &crate::websocket_session::WebSocketMessageInfo,
) -> crate::protocol_event::ProtocolEvent {
    crate::protocol_event::ProtocolEvent {
        timestamp: chrono::Utc::now(),
        connection_id,
        kind: crate::protocol_event::ProtocolEventKind::WebSocketFrame {
            session_id,
            direction: info.direction,
            fin: info.fin,
            opcode: info.opcode,
            rsv: info.rsv,
            payload_length: info.payload_length,
        },
    }
}

/// Relay WebSocket messages between client and server, recording each message
/// for capture. Uses tokio-tungstenite for proper RFC 6455 frame parsing.
async fn relay_websocket(
    client_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    server_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    tx_id: uuid::Uuid,
    captures: CaptureWriter,
    connection_id: uuid::Uuid,
    pipeline: ProtocolEventPipeline,
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
                    let pe = ws_frame_event(connection_id, session_id, &info);
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
    let pipe_s2c = pipeline;
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
                    let pe = ws_frame_event(connection_id, session_id, &info);
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

    // Run both directions concurrently; when either finishes, the session is done.
    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut session = WebSocketSession::new(tx_id);
    session.id = session_id;
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

    if let Err(e) = captures.write_websocket_session(&session).await {
        error!("failed to write websocket session: {}", e);
    }
}

fn message_to_info(
    msg: &tokio_tungstenite::tungstenite::Message,
    direction: crate::websocket_session::MessageDirection,
) -> crate::websocket_session::WebSocketMessageInfo {
    use crate::websocket_session::WebSocketMessageInfo;
    let (opcode, payload_length, fin, rsv) = match msg {
        // Assembled messages: tungstenite has already defragmented, so FIN is
        // implicitly true and RSV bits are not available.
        tokio_tungstenite::tungstenite::Message::Text(s) => (1, s.len() as u64, true, 0u8),
        tokio_tungstenite::tungstenite::Message::Binary(b) => (2, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Ping(b) => (9, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Pong(b) => (10, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Close(frame) => {
            let len = frame
                .as_ref()
                .map(|f| 2 + f.reason.len() as u64)
                .unwrap_or(0);
            (8, len, true, 0)
        }
        // Raw Frame variant: extract actual FIN and RSV bits from header.
        tokio_tungstenite::tungstenite::Message::Frame(f) => {
            let hdr = f.header();
            let rsv_bits = ((hdr.rsv1 as u8) << 2) | ((hdr.rsv2 as u8) << 1) | (hdr.rsv3 as u8);
            (
                u8::from(hdr.opcode),
                f.payload().len() as u64,
                hdr.is_final,
                rsv_bits,
            )
        }
    };
    WebSocketMessageInfo {
        direction,
        opcode,
        payload_length,
        fin,
        rsv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureWriter;
    use crate::proxy::test_support::make_shared_with_cfg;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Request};
    use rstest::rstest;
    use std::sync::Arc as StdArc;
    use tokio::time::Instant;
    use uuid::Uuid;

    fn test_pe_pipeline() -> ProtocolEventPipeline {
        ProtocolEventPipeline::new(
            StdArc::new(crate::config::Config::default()),
            StdArc::new(crate::protocol_event_store::ProtocolEventStore::new(
                300, 100,
            )),
        )
    }

    #[test]
    fn is_websocket_upgrade_detects_valid_upgrade() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn is_websocket_upgrade_case_insensitive() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "upgrade")
            .header("upgrade", "WebSocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[rstest]
    #[case(Some("keep-alive"), Some("websocket"), false)]
    #[case(Some("Upgrade"), None, false)]
    #[case(None, Some("websocket"), false)]
    #[case(None, None, false)]
    #[case(Some("Upgrade"), Some("h2c"), false)]
    // Connection contains "upgrade" only as a substring of another token —
    // RFC 7230 requires the literal "upgrade" token to be present.
    #[case(Some("super-upgrade"), Some("websocket"), false)]
    #[case(Some("upgrades"), Some("websocket"), false)]
    fn is_websocket_upgrade_negative(
        #[case] connection: Option<&str>,
        #[case] upgrade: Option<&str>,
        #[case] expected: bool,
    ) {
        let mut builder = Request::builder()
            .method("GET")
            .uri("http://example.com/ws");
        if let Some(c) = connection {
            builder = builder.header("connection", c);
        }
        if let Some(u) = upgrade {
            builder = builder.header("upgrade", u);
        }
        let req = builder.body(Full::new(Bytes::new()).boxed()).unwrap();
        assert_eq!(is_websocket_upgrade(&req), expected);
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
                cw_clone,
                uuid::Uuid::new_v4(),
                test_pe_pipeline(),
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
        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
    async fn connect_upstream_for_upgrade_fails_without_host() {
        let uri: Uri = "/no-host".parse().unwrap();
        let result = connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_fails_with_closed_port() {
        // pick a port that's not listening
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse().unwrap();
        let result = connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_upstream_connect_error() -> anyhow::Result<()> {
        // Test that handle_websocket_upgrade returns 502 when upstream is unreachable
        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None).await?;

        // Build a request targeting a closed port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = l.local_addr()?.port();
        drop(l);

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        // Create a fake OnUpgrade that will never complete
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        assert_eq!(resp.status().as_u16(), 502);

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_non_101_response() -> anyhow::Result<()> {
        // Start a plain HTTP server that returns 400 for upgrade requests
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
                let _ = socket.try_write(resp);
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        // Server returned 400, so proxy should forward it
        assert_eq!(resp.status().as_u16(), 400);

        let _ = server_task.await;
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
                cw_clone,
                uuid::Uuid::new_v4(),
                test_pe_pipeline(),
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

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
                cw_clone,
                uuid::Uuid::new_v4(),
                test_pe_pipeline(),
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

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Should still write a session record (with empty messages)
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

    #[tokio::test]
    async fn connect_upstream_for_upgrade_plain_tcp_success() -> anyhow::Result<()> {
        // Start a simple HTTP server that accepts connections
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.try_write(resp);
            }
        });

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let (mut sender, _handle) =
            connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await?;

        // Verify we can send a request
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{}/ws", port))
            .body(Full::new(Bytes::new()))?;
        let resp = sender.send_request(req).await?;
        assert_eq!(resp.status().as_u16(), 200);

        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_send_request_error() -> anyhow::Result<()> {
        // Start a server that accepts TCP connections then immediately closes them
        // This will cause the hyper handshake to succeed but send_request to fail
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            // Accept connection then drop it immediately
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        // Server dropped connection, send_request should fail -> 502
        assert_eq!(resp.status().as_u16(), 502);

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
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
                cw_clone,
                uuid::Uuid::new_v4(),
                test_pe_pipeline(),
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

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
