// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration tests for the live capture stream endpoint (`/_lint_http/stream`).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lint_http::config::Config;

mod common;
use common::start_run_proxy_and_wait;

/// Read from `stream`, accumulating into a buffer, until it contains `needle`
/// or the deadline passes. Returns everything read so far (headers included).
async fn read_until(
    stream: &mut TcpStream,
    needle: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| anyhow::anyhow!("timeout waiting for {needle:?}"))?;
        let n = tokio::time::timeout(remaining, stream.read(&mut chunk)).await??;
        if n == 0 {
            anyhow::bail!(
                "stream closed before {needle:?}; got: {}",
                String::from_utf8_lossy(&buf)
            );
        }
        buf.extend_from_slice(&chunk[..n]);
        let s = String::from_utf8_lossy(&buf);
        if s.contains(needle) {
            return Ok(s.into_owned());
        }
    }
}

#[tokio::test]
async fn live_stream_pushes_committed_transaction() -> anyhow::Result<()> {
    // Upstream the proxy will forward to.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock)
        .await;

    let mut cfg = Config::default();
    cfg.tls.enabled = false;
    cfg.general.live_stream_enabled = true;
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg).await?;

    // Open the SSE stream and give the handler a moment to subscribe before any
    // transaction commits.
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /_lint_http/stream HTTP/1.1\r\nHost: proxy\r\n\r\n")
        .await?;
    sleep(Duration::from_millis(300)).await;

    // Drive a forward-proxy request through the proxy to the upstream.
    let mut client = TcpStream::connect(addr).await?;
    let req = format!(
        "GET http://127.0.0.1:{}/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        mock.address().port(),
        mock.address().port()
    );
    client.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp)).await??;
    assert!(
        String::from_utf8_lossy(&resp).contains("pong"),
        "proxied request should succeed: {}",
        String::from_utf8_lossy(&resp)
    );

    // The committed transaction is pushed to the stream as an SSE data event.
    let body = read_until(&mut stream, "/ping", Duration::from_secs(5)).await?;
    assert!(body.contains("200"), "stream response status: {body}");
    assert!(
        body.to_lowercase().contains("text/event-stream"),
        "stream content-type: {body}"
    );
    assert!(body.contains("data:"), "expected an SSE data event: {body}");
    assert!(
        body.contains("\"method\":\"GET\""),
        "event should carry the transaction: {body}"
    );

    handle.abort();
    let _ = tokio::fs::remove_file(&cap_path).await;
    Ok(())
}

#[tokio::test]
async fn live_stream_disabled_returns_404() -> anyhow::Result<()> {
    // Default config leaves live_stream_enabled = false.
    let mut cfg = Config::default();
    cfg.tls.enabled = false;
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg).await?;

    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /_lint_http/stream HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n")
        .await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut resp)).await??;
    let s = String::from_utf8_lossy(&resp);
    assert!(s.contains("404"), "expected 404 when disabled, got: {s}");

    handle.abort();
    let _ = tokio::fs::remove_file(&cap_path).await;
    Ok(())
}
