// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration test: WebSocket upgrade through the proxy with frame relay and capture.

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lint_http::config::Config;

mod common;
use common::{start_run_proxy_and_wait, tls_config, TempFiles};

/// Start a minimal WebSocket echo server on a random port.
/// Returns the address it's listening on.
async fn start_ws_echo_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let ws = tokio_tungstenite::accept_async(stream).await;
                let mut ws = match ws {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                // Echo messages back
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_close() {
                        let _ = ws.close(None).await;
                        break;
                    }
                    if ws.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn websocket_upgrade_through_proxy_captures_session() -> anyhow::Result<()> {
    // Start a WebSocket echo server
    let ws_addr = start_ws_echo_server().await;

    // Start the proxy
    let cfg = Config::default();
    let mut temp = TempFiles::new();
    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, &mut temp).await?;

    // Connect to the proxy and perform WebSocket handshake via HTTP upgrade
    // Connect TCP to proxy5
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await?;

    // Build a raw HTTP upgrade request through the proxy
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let req = format!(
        "GET http://127.0.0.1:{}/ws HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {}\r\n\
         \r\n",
        ws_addr.port(),
        ws_addr.port(),
        ws_key
    );
    tcp.write_all(req.as_bytes()).await?;

    // Read the 101 response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("proxy closed connection before completing HTTP response");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let resp_str = String::from_utf8_lossy(&buf);
    assert!(
        resp_str.contains("101"),
        "Expected 101 response, got: {}",
        resp_str
    );

    // Now the connection is upgraded. Wrap in WebSocket client.
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        tcp,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    let (mut write, mut read) = ws.split();

    // Send a text message
    write
        .send(tokio_tungstenite::tungstenite::Message::Text("ping".into()))
        .await?;

    // Receive echo
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), read.next())
        .await?
        .unwrap()?;
    assert_eq!(
        msg,
        tokio_tungstenite::tungstenite::Message::Text("ping".into())
    );

    // Send close
    write
        .send(tokio_tungstenite::tungstenite::Message::Close(Some(
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                reason: "done".into(),
            },
        )))
        .await?;

    // Read close response
    let _close_msg = tokio::time::timeout(std::time::Duration::from_secs(5), read.next()).await;
    drop(write);
    drop(read);

    // The relay writes the session capture asynchronously after the close
    // handshake, and the capture writer flushes on its own schedule, so poll
    // until both the 101 transaction and the websocket session land rather than
    // relying on a fixed sleep (which races on a slow/loaded CI runner).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let content = loop {
        let content = tokio::fs::read_to_string(&captures_path)
            .await
            .unwrap_or_default();
        let records = content.lines().filter(|l| !l.trim().is_empty()).count();
        if records >= 2 || std::time::Instant::now() > deadline {
            break content;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    // Should have at least 2 records: the 101 transaction and the websocket session
    assert!(
        lines.len() >= 2,
        "Expected at least 2 capture records, got {}: {}",
        lines.len(),
        content
    );

    // Find the 101 transaction
    let mut found_101 = false;
    let mut found_ws_session = false;
    let mut tx_id = String::new();

    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line)?;
        if v["type"].as_str() == Some("http_transaction")
            && v["response"]["status"].as_u64() == Some(101)
        {
            found_101 = true;
            assert_eq!(v["was_upgraded"].as_bool(), Some(true));
            assert_eq!(v["upgrade_protocol"].as_str(), Some("websocket"));
            tx_id = v["id"].as_str().unwrap_or("").to_string();
        }
        if v["type"].as_str() == Some("websocket_session") {
            found_ws_session = true;
            // Verify it links to the 101 transaction
            if !tx_id.is_empty() {
                assert_eq!(v["transaction_id"].as_str(), Some(tx_id.as_str()));
            }
            // Should have messages
            let messages = v["messages"].as_array().unwrap();
            assert!(
                !messages.is_empty(),
                "WebSocket session should have messages"
            );
            // Should have a close code
            assert_eq!(v["close_code"].as_u64(), Some(1000));
        }
    }

    assert!(found_101, "Should have a 101 transaction in captures");
    assert!(
        found_ws_session,
        "Should have a websocket_session in captures"
    );

    // Cleanup
    handle.abort();
    Ok(())
}

/// The wss:// composition, previously untested end to end: CONNECT to the
/// proxy, TLS-MITM inside the tunnel with the proxy's own CA, then a
/// WebSocket upgrade and echo over the TLS client leg. The origin leg stays
/// plain TCP (the inner request names an absolute http:// target), so the
/// test needs no origin-side trust store.
#[tokio::test]
async fn websocket_upgrade_through_connect_mitm_tunnel() -> anyhow::Result<()> {
    use rustls::pki_types::pem::PemObject;

    let ws_addr = start_ws_echo_server().await;

    let mut temp = TempFiles::new();
    let cfg = tls_config(&mut temp);
    let cert_path = common::ca_cert_path(&cfg);

    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, &mut temp).await?;

    // CONNECT to the proxy; the authority names the MITM certificate's domain.
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await?;
    tcp.write_all(b"CONNECT wsecho.test:443 HTTP/1.1\r\nHost: wsecho.test:443\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("proxy closed connection during CONNECT");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 2"),
        "CONNECT refused: {}",
        String::from_utf8_lossy(&buf)
    );

    // TLS handshake inside the tunnel, trusting the proxy's CA; http/1.1 only
    // so the upgrade request is spoken over the protocol it belongs to.
    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(&cert_path)?
        .collect::<Result<Vec<_>, _>>()?;
    root_store.add_parsable_certificates(certs);
    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_cfg));
    let server_name = rustls::pki_types::ServerName::try_from("wsecho.test".to_string())?;
    let mut tls = connector.connect(server_name, tcp).await?;

    // The WebSocket handshake through the tunnel.
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let req = format!(
        "GET http://127.0.0.1:{port}/ws HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         \r\n",
        port = ws_addr.port(),
    );
    tls.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("proxy closed the tunnel before the upgrade response");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let resp_str = String::from_utf8_lossy(&buf);
    assert!(resp_str.contains("101"), "expected 101, got: {resp_str}");

    // Echo a message over the upgraded TLS stream.
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        tls,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    let (mut write, mut read) = ws.split();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "tunneled".into(),
        ))
        .await?;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), read.next())
        .await?
        .unwrap()?;
    assert_eq!(
        msg,
        tokio_tungstenite::tungstenite::Message::Text("tunneled".into())
    );
    write
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), read.next()).await;
    drop(write);
    drop(read);

    // Both the 101 transaction and the linked session land in the capture.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let content = loop {
        let content = tokio::fs::read_to_string(&captures_path)
            .await
            .unwrap_or_default();
        if content
            .lines()
            .filter(|l| l.contains("websocket_session"))
            .count()
            >= 1
            || std::time::Instant::now() > deadline
        {
            break content;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    let mut tx_id = String::new();
    let mut found_session = false;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        if v["type"].as_str() == Some("http_transaction")
            && v["response"]["status"].as_u64() == Some(101)
        {
            assert_eq!(v["was_upgraded"].as_bool(), Some(true));
            tx_id = v["id"].as_str().unwrap_or("").to_string();
        }
        if v["type"].as_str() == Some("websocket_session") {
            found_session = true;
            assert!(!v["messages"].as_array().unwrap().is_empty());
            if !tx_id.is_empty() {
                assert_eq!(v["transaction_id"].as_str(), Some(tx_id.as_str()));
            }
        }
    }
    assert!(!tx_id.is_empty(), "no 101 transaction captured: {content}");
    assert!(found_session, "no websocket session captured: {content}");

    handle.abort();
    Ok(())
}

/// An origin that writes a frame in the same packet as its 101: hyper may
/// have already buffered those bytes when the upgrade completes, and the
/// relay must still see them — `TokioIo` yields them through the first read,
/// so the frame reaches both the client and the capture.
#[tokio::test]
async fn a_frame_sent_with_the_101_is_relayed_and_recorded() -> anyhow::Result<()> {
    // Raw origin: read the handshake, answer 101 + an unmasked text frame
    // ("hi") in ONE write.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let key = String::from_utf8_lossy(&req)
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("sec-websocket-key:")
                        .then(|| l.split(':').nth(1).unwrap().trim().to_string())
                })
                .unwrap_or_default();
            let accept = {
                use base64::Engine;
                use sha1::{Digest, Sha1};
                let mut h = Sha1::new();
                h.update(key.as_bytes());
                h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                base64::engine::general_purpose::STANDARD.encode(h.finalize())
            };
            let mut one_write = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            one_write.extend([0x81, 0x02, b'h', b'i']);
            let _ = sock.write_all(&one_write).await;
            // Keep the socket open long enough for the relay to read it.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });

    let cfg = Config::default();
    let mut temp = TempFiles::new();
    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, &mut temp).await?;

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await?;
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let req = format!(
        "GET http://{origin}/ws HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\r\n",
        origin = origin_addr,
    );
    tcp.write_all(req.as_bytes()).await?;

    // Read the 101 head, then the frame the origin sent alongside it.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let frame_bytes = loop {
        let n = tcp.read(&mut tmp).await?;
        anyhow::ensure!(n > 0, "proxy closed before delivering the frame");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body = &buf[head_end + 4..];
            if body.len() >= 4 {
                break body.to_vec();
            }
        }
    };
    assert!(String::from_utf8_lossy(&buf).contains("101"));
    assert_eq!(&frame_bytes[..4], &[0x81, 0x02, b'h', b'i'][..]);

    // Close the client leg: the session record is written when both
    // directions have ended, and the origin's side drops on its own.
    drop(tcp);

    // The frame the origin folded into the 101 packet is in the record.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let found = loop {
        let content = tokio::fs::read_to_string(&captures_path)
            .await
            .unwrap_or_default();
        let found = content.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .map(|v| {
                    v["type"] == "websocket_session"
                        && v["messages"].as_array().is_some_and(|m| {
                            m.iter().any(|f| {
                                f["direction"] == "server"
                                    && f["opcode"].as_u64() == Some(1)
                                    && f["payload_length"].as_u64() == Some(2)
                            })
                        })
                })
                .unwrap_or(false)
        });
        if found || std::time::Instant::now() > deadline {
            break found;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    assert!(found, "the with-101 frame never reached the capture");

    handle.abort();
    Ok(())
}

/// Build one RFC 6455 frame, raw.
fn raw_frame(fin: bool, rsv1: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test frames stay in len7");
    let mut out = vec![
        (if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode,
        (if mask.is_some() { 0x80 } else { 0 }) | payload.len() as u8,
    ];
    match mask {
        Some(k) => {
            out.extend(k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend(payload),
    }
    out
}

/// The frames the frame rules were written for, live and end to end: a
/// fragmented message, an unmasked client frame, and an RSV1 frame with
/// nothing negotiated — each recorded with its real header bits, and the
/// masking and RSV rules each producing their finding on the session record.
#[tokio::test]
async fn defective_frames_produce_live_findings() -> anyhow::Result<()> {
    // A raw, tolerant origin: complete the 101 handshake, then read and
    // discard until EOF — so one defective frame cannot end the session
    // before the next is observed (a conforming endpoint would fail the
    // connection, which is its right and not this test's subject).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let key = String::from_utf8_lossy(&req)
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("sec-websocket-key:")
                        .then(|| l.split(':').nth(1).unwrap().trim().to_string())
                })
                .unwrap_or_default();
            let accept = {
                use base64::Engine;
                use sha1::{Digest, Sha1};
                let mut h = Sha1::new();
                h.update(key.as_bytes());
                h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                base64::engine::general_purpose::STANDARD.encode(h.finalize())
            };
            let _ = sock
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await;
            while sock.read(&mut buf).await.unwrap_or(0) > 0 {}
        }
    });

    let cfg = Config {
        lint: lint_http_core::test_helpers::make_test_config_with_enabled_rules(&[
            "websocket_frame_masking",
            "websocket_frame_rsv_bits",
            "websocket_frame_opcode_sequence",
        ]),
        ..Default::default()
    };
    let mut temp = TempFiles::new();
    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, &mut temp).await?;

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await?;
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        uuid::Uuid::new_v4().as_bytes(),
    );
    tcp.write_all(
        format!(
            "GET http://{origin}/ws HTTP/1.1\r\n\
             Host: {origin}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\r\n",
            origin = origin_addr,
        )
        .as_bytes(),
    )
    .await?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tcp.read(&mut tmp).await?;
        anyhow::ensure!(n > 0, "proxy closed during handshake");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    anyhow::ensure!(String::from_utf8_lossy(&buf).contains("101"));

    // The defect parade: a fragmented text message (legal — it exercises the
    // fin/continuation path the old relay could never record), an unmasked
    // client frame, an RSV1 frame with nothing negotiated, a clean close.
    let key = [5u8, 6, 7, 8];
    let mut wire = raw_frame(false, false, 0x1, Some(key), b"he");
    wire.extend(raw_frame(true, false, 0x0, Some(key), b"llo"));
    wire.extend(raw_frame(true, false, 0x1, None, b"naked"));
    wire.extend(raw_frame(true, true, 0x1, Some(key), b"rsv"));
    wire.extend(raw_frame(
        true,
        false,
        0x8,
        Some(key),
        &1000u16.to_be_bytes(),
    ));
    tcp.write_all(&wire).await?;
    drop(tcp);

    // The session record carries the real header bits and the findings.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let session = loop {
        let content = tokio::fs::read_to_string(&captures_path)
            .await
            .unwrap_or_default();
        let session = content.lines().find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .filter(|v| v["type"] == "websocket_session")
        });
        if session.is_some() || std::time::Instant::now() > deadline {
            break session;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    .expect("a websocket session in the capture");

    let messages = session["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 5, "all five frames recorded: {messages:?}");
    assert_eq!(messages[0]["fin"].as_bool(), Some(false), "first fragment");
    assert_eq!(messages[1]["opcode"].as_u64(), Some(0), "continuation");
    assert_eq!(messages[1]["fin"].as_bool(), Some(true));
    assert_eq!(
        messages[2]["masked"].as_bool(),
        Some(false),
        "unmasked frame"
    );
    assert_eq!(messages[3]["rsv"].as_u64(), Some(0b100), "RSV1 recorded");
    assert_eq!(session["client_close_code"].as_u64(), Some(1000));

    let violations: Vec<&str> = session["violations"]
        .as_array()
        .map(|v| v.iter().filter_map(|x| x["rule"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        violations.contains(&"websocket_frame_masking"),
        "the unmasked client frame is a live finding: {violations:?}"
    );
    assert!(
        violations.contains(&"websocket_frame_rsv_bits"),
        "the un-negotiated RSV1 bit is a live finding: {violations:?}"
    );

    handle.abort();
    Ok(())
}

/// Extension negotiation passes through end to end: the client's offer
/// reaches the origin, the origin's acceptance reaches the client inside the
/// 101, an RSV1 frame (what a permessage-deflate origin sends) survives the
/// relay — and the RSV rule, enabled, stands down because the handshake it
/// can now see accepted an extension.
#[tokio::test]
async fn extension_negotiation_flows_end_to_end() -> anyhow::Result<()> {
    // A raw origin that requires the offer, accepts it in the 101, then sends
    // one RSV1 "compressed" text frame (no real deflate needed — the relay
    // never reads payloads) and reads until EOF.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req_str = String::from_utf8_lossy(&req).to_string();
            assert!(
                req_str.to_ascii_lowercase().contains("permessage-deflate"),
                "the client's extension offer must reach the origin: {req_str}"
            );
            let key = req_str
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("sec-websocket-key:")
                        .then(|| l.split(':').nth(1).unwrap().trim().to_string())
                })
                .unwrap_or_default();
            let accept = {
                use base64::Engine;
                use sha1::{Digest, Sha1};
                let mut h = Sha1::new();
                h.update(key.as_bytes());
                h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                base64::engine::general_purpose::STANDARD.encode(h.finalize())
            };
            let mut reply = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
            )
            .into_bytes();
            // RSV1 set, text, unmasked (server side), 2 bytes.
            reply.extend([0xC1, 0x02, 0xAB, 0xCD]);
            let _ = sock.write_all(&reply).await;
            while sock.read(&mut buf).await.unwrap_or(0) > 0 {}
        }
    });

    let cfg = Config {
        lint: lint_http_core::test_helpers::make_test_config_with_enabled_rules(&[
            "websocket_frame_rsv_bits",
        ]),
        ..Default::default()
    };
    let mut temp = TempFiles::new();
    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, &mut temp).await?;

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await?;
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        uuid::Uuid::new_v4().as_bytes(),
    );
    tcp.write_all(
        format!(
            "GET http://{origin}/ws HTTP/1.1\r\n\
             Host: {origin}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            origin = origin_addr,
        )
        .as_bytes(),
    )
    .await?;

    // The 101 reaching the client carries the origin's acceptance, and the
    // RSV1 frame follows it through the relay.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let frame_bytes = loop {
        let n = tcp.read(&mut tmp).await?;
        anyhow::ensure!(n > 0, "proxy closed before delivering the frame");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body = &buf[head_end + 4..];
            if body.len() >= 4 {
                break body.to_vec();
            }
        }
    };
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    assert!(head.contains("101"));
    assert!(
        head.contains("sec-websocket-extensions: permessage-deflate"),
        "the origin's acceptance must reach the client: {head}"
    );
    assert_eq!(&frame_bytes[..4], &[0xC1, 0x02, 0xAB, 0xCD][..]);
    drop(tcp);

    // The session records the acceptance and the RSV1 frame — and the enabled
    // RSV rule stands down, because the handshake licensed the bit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let session = loop {
        let content = tokio::fs::read_to_string(&captures_path)
            .await
            .unwrap_or_default();
        let session = content.lines().find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .filter(|v| v["type"] == "websocket_session")
        });
        if session.is_some() || std::time::Instant::now() > deadline {
            break session;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    .expect("a websocket session in the capture");

    assert!(
        session["extensions"]
            .to_string()
            .contains("permessage-deflate"),
        "the session records what the 101 accepted: {}",
        session["extensions"]
    );
    let rsv_frame = session["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["rsv"].as_u64() == Some(0b100))
        .expect("the RSV1 frame is recorded");
    assert_eq!(rsv_frame["direction"].as_str(), Some("server"));
    let violations = session["violations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        violations.is_empty(),
        "an accepted extension stands the RSV finding down: {violations:?}"
    );

    handle.abort();
    Ok(())
}
