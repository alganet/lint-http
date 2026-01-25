// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use lint_http::config::Config;
use lint_http::rules::RuleConfigEngine;

mod common;
use common::start_run_proxy_and_wait;

async fn do_connect_and_get_response(
    proxy_addr: SocketAddr,
    connect_host: &str,
    connect_port: u16,
) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
        host = connect_host,
        port = connect_port
    );
    stream.write_all(connect.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() > deadline {
            anyhow::bail!("timeout reading CONNECT response");
        }
        let n = match timeout(Duration::from_millis(500), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => {
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                } else {
                    anyhow::bail!("unexpected EOF before complete CONNECT response");
                }
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                continue;
            }
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[tokio::test]
async fn connect_passthrough_tunnels_raw_tcp() -> anyhow::Result<()> {
    // start toy server that expects 'ping' and replies 'pong'
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4];
            if socket.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                let _ = socket.write_all(b"pong").await;
            }
        }
    });

    // Start proxy with passthrough for 127.0.0.1
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());
    // Use a literal IP in passthrough domain so the proxy connects to the toy server
    cfg.tls.passthrough_domains = vec!["127.0.0.1".into()];

    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // CONNECT and then send raw ping/pong to the toy server IP
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = port
    );
    stream.write_all(connect.as_bytes()).await?;

    let mut hdr = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = timeout(Duration::from_millis(500), stream.read(&mut tmp)).await??;
        if n == 0 {
            anyhow::bail!("unexpected EOF reading CONNECT response");
        }
        hdr.extend_from_slice(&tmp[..n]);
        if hdr.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let hdrs = String::from_utf8_lossy(&hdr);
    assert!(hdrs.starts_with("HTTP/1.1 200"));

    // send ping and expect pong
    stream.write_all(b"ping").await?;
    let mut resp = [0u8; 4];
    timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(&resp, b"pong");

    // cleanup
    handle.abort();
    let _ = handle.await;
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(cap_path).await;
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn connect_passthrough_upstream_unavailable() -> anyhow::Result<()> {
    // pick a port by binding then dropping the listener
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    // Start proxy with passthrough for 127.0.0.1
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());
    // Use a literal IP in passthrough domain so the proxy connects to the toy server
    cfg.tls.passthrough_domains = vec!["127.0.0.1".into()];

    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // CONNECT and expect it to succeed but subsequent I/O to close
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = port
    );
    stream.write_all(connect.as_bytes()).await?;

    // read headers
    let mut hdr = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = timeout(Duration::from_millis(500), stream.read(&mut tmp)).await??;
        if n == 0 {
            anyhow::bail!("unexpected EOF reading CONNECT response");
        }
        hdr.extend_from_slice(&tmp[..n]);
        if hdr.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let hdrs = String::from_utf8_lossy(&hdr);
    assert!(hdrs.starts_with("HTTP/1.1 200"));

    // Try to write and expect read to return 0 (connection closed) or timeout quickly
    stream.write_all(b"ping").await?;
    let mut read_buf = [0u8; 4];
    let r = timeout(Duration::from_secs(1), stream.read(&mut read_buf)).await;
    // Either EOF (Ok(Ok(0))) or timeout; any non-zero bytes are unexpected and should fail
    match r {
        Ok(Ok(0)) => { /* expected: closed */ }
        Ok(Ok(n)) => {
            anyhow::bail!("unexpected {} bytes read from upstream after CONNECT", n);
        }
        Ok(Err(_)) => { /* IO error acceptable */ }
        Err(_) => { /* timeout acceptable */ }
    }

    // cleanup
    handle.abort();
    let _ = handle.await;
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(cap_path).await;
    Ok(())
}

#[tokio::test]
async fn connect_without_tls_returns_405() -> anyhow::Result<()> {
    // Start proxy with TLS disabled
    let mut cfg = Config::default();
    cfg.tls.enabled = false;
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // CONNECT and read response
    let res = do_connect_and_get_response(addr, "example.com", 12345).await?;
    assert!(res.starts_with("HTTP/1.1 405"));
    assert!(res.contains("CONNECT not supported (TLS disabled)"));

    handle.abort();
    let _ = handle.await;
    let _ = tokio::fs::remove_file(cap_path).await;
    Ok(())
}
