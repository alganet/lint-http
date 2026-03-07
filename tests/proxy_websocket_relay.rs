// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration test: WebSocket upgrade through the proxy with frame relay and capture.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lint_http::config::Config;
use lint_http::rules::RuleConfigEngine;

mod common;
use common::start_run_proxy_and_wait;

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
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg, engine).await?;

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

    // Give the proxy time to write the session capture
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Read captures file
    let content = tokio::fs::read_to_string(&captures_path).await?;
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
        if (v.get("type").is_none() || v["type"].as_str() == Some("http_transaction"))
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
    let _ = tokio::fs::remove_file(&captures_path).await;
    Ok(())
}
