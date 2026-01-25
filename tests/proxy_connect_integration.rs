// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::start_run_proxy_and_wait;

use lint_http::config::Config;
use lint_http::rules::RuleConfigEngine;

// Unified helper: perform CONNECT, do TLS handshake trusting `ca_cert_path`, optionally advertise ALPNs, optionally send an inner request.
// Returns (negotiated_alpn, optional_response_bytes).
async fn perform_connect_and_tls_with_alpn_opt(
    proxy_addr: SocketAddr,
    connect_host: &str,
    connect_port: u16,
    ca_cert_path: &std::path::Path,
    alpn_protocols: Option<&[&str]>,
    inner_request: Option<&str>,
) -> anyhow::Result<(Option<String>, Option<Vec<u8>>)> {
    use rustls::client::ClientConfig;
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;
    use rustls_pemfile;
    use std::fs::File;
    use std::io::BufReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect TCP
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;

    // Send CONNECT
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
        host = connect_host,
        port = connect_port
    );
    stream.write_all(connect.as_bytes()).await?;

    // Read response headers until \r\n\r\n
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() > deadline {
            return Err(anyhow::anyhow!("timeout reading CONNECT response"));
        }
        let n = match timeout(Duration::from_millis(500), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => {
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                } else {
                    return Err(anyhow::anyhow!("unexpected EOF reading CONNECT response"));
                }
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => continue,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let hdrs = String::from_utf8_lossy(&buf);
    if !hdrs.starts_with("HTTP/1.1 200") && !hdrs.starts_with("HTTP/1.1 2") {
        return Err(anyhow::anyhow!("CONNECT not successful: {}", hdrs));
    }

    // Setup TLS client config trusting ca_cert_path
    let mut root_store = RootCertStore::empty();
    let mut f = BufReader::new(File::open(ca_cert_path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut f).collect::<Result<Vec<_>, _>>()?;
    // Pass the parsed certificate DER buffers directly to RootCertStore
    root_store.add_parsable_certificates(certs);
    let mut client_cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set ALPN if requested
    if let Some(alpns) = alpn_protocols {
        client_cfg.alpn_protocols = alpns.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));
    let server_name = ServerName::try_from(connect_host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name"))?;

    let mut tls = connector.connect(server_name, stream).await?;

    // Read negotiated ALPN from client-side connection
    let negotiated = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|v| String::from_utf8_lossy(v).into_owned());

    // If requested, send inner request and read response
    let resp_opt = if let Some(req) = inner_request {
        tls.write_all(req.as_bytes()).await?;

        // Read until we have some body or timeout
        let mut resp = Vec::new();
        let deadline2 = Instant::now() + Duration::from_secs(3);
        loop {
            if Instant::now() > deadline2 {
                break;
            }
            let mut tmp2 = [0u8; 1024];
            match timeout(Duration::from_millis(500), tls.read(&mut tmp2)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    resp.extend_from_slice(&tmp2[..n]);
                    // quick heuristic: stop if we see mock body 'ok'
                    if resp.windows(2).any(|w| w == b"ok") {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => continue,
            }
        }
        Some(resp)
    } else {
        None
    };

    Ok((negotiated, resp_opt))
}

// Backwards-compatible wrapper kept for tests: forwards to unified helper.
async fn perform_connect_and_tls_with_alpn(
    proxy_addr: SocketAddr,
    connect_host: &str,
    connect_port: u16,
    ca_cert_path: &std::path::Path,
    alpn_protocols: &[&str],
    inner_request: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let (neg, _resp) = perform_connect_and_tls_with_alpn_opt(
        proxy_addr,
        connect_host,
        connect_port,
        ca_cert_path,
        Some(alpn_protocols),
        inner_request,
    )
    .await?;
    Ok(neg)
}

#[tokio::test]
async fn connect_tls_full_forwarding() -> anyhow::Result<()> {
    // 1) Start upstream mock
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    // 2) Build config with TLS enabled and temp CA paths
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

    // 3) Start proxy and wait
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // 4) Perform CONNECT + TLS + inner request
    let host = "example.com";
    let inner = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        mock.address().port(),
        mock.address().port()
    );

    let (_neg, resp_opt) = perform_connect_and_tls_with_alpn_opt(
        addr,
        host,
        mock.address().port(),
        &cert_path,
        None,
        Some(&inner),
    )
    .await?;
    let resp_bytes = resp_opt.ok_or_else(|| anyhow::anyhow!("no response bytes"))?;
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    assert!(resp_str.contains("200"));

    // 5) Verify upstream mock saw request
    let mut attempts = 0u32;
    let reqs = loop {
        attempts += 1;
        let r = mock.received_requests().await.expect("received requests");
        if !r.is_empty() || attempts > 10 {
            break r;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert!(!reqs.is_empty());
    assert_eq!(reqs[0].method.as_str(), "GET");
    assert_eq!(reqs[0].url.path(), "/");

    // 6) Cleanup
    handle.abort();
    let _ = handle.await;

    // remove temp files
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(&cap_path).await;

    Ok(())
}

#[tokio::test]
async fn connect_tls_alpn_client_selects_http1() -> anyhow::Result<()> {
    // 1) Start upstream mock
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    // 2) Build config with TLS enabled and temp CA paths
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

    // 3) Start proxy and wait
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // 4) Perform CONNECT + TLS + inner request, advertising http/1.1
    let host = "example.com";
    let inner = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        mock.address().port(),
        mock.address().port()
    );

    let negotiated = perform_connect_and_tls_with_alpn(
        addr,
        host,
        mock.address().port(),
        &cert_path,
        &["http/1.1"],
        Some(&inner),
    )
    .await?;

    assert_eq!(negotiated.as_deref(), Some("http/1.1"));

    // 5) Verify upstream mock saw request
    let mut attempts = 0u32;
    let reqs = loop {
        attempts += 1;
        let r = mock.received_requests().await.expect("received requests");
        if !r.is_empty() || attempts > 10 {
            break r;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert!(!reqs.is_empty());
    assert_eq!(reqs[0].method.as_str(), "GET");
    assert_eq!(reqs[0].url.path(), "/");

    // 6) Cleanup
    handle.abort();
    let _ = handle.await;

    // remove temp files
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(&cap_path).await;

    Ok(())
}

#[tokio::test]
async fn connect_tls_alpn_mismatch_fails_handshake() -> anyhow::Result<()> {
    // 1) Start upstream mock
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    // 2) Build config with TLS enabled and temp CA paths
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

    // 3) Start proxy and wait
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // 4) Perform CONNECT + TLS + inner request, advertising only 'h3' which does not match server
    let host = "example.com";
    let inner = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        mock.address().port(),
        mock.address().port()
    );

    // Expect the TLS handshake to fail because the client advertises an ALPN with
    // no overlap with the server's offered protocols (server offers h2/http/1.1).
    let err = perform_connect_and_tls_with_alpn(
        addr,
        host,
        mock.address().port(),
        &cert_path,
        &["h3"],
        Some(&inner),
    )
    .await
    .expect_err("handshake should fail with NoApplicationProtocol");
    let msg = format!("{}", err);
    assert!(msg.contains("NoApplicationProtocol") || msg.contains("no application protocol"));

    // 5) Because the TLS handshake failed due to ALPN mismatch, the upstream
    // mock should not have received any requests.
    let reqs = mock.received_requests().await.expect("received requests");
    assert!(reqs.is_empty());

    // 6) Cleanup
    handle.abort();
    let _ = handle.await;

    // remove temp files
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(&cap_path).await;

    Ok(())
}
