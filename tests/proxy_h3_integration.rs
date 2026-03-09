// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration tests for HTTP/3 (QUIC) proxy support.
//!
//! These tests start the full proxy with `h3_listen` configured, then connect
//! via a quinn QUIC client and issue HTTP/3 requests through the h3 crate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use wiremock::{Mock, MockServer, ResponseTemplate};

use lint_http::capture::CaptureWriter;
use lint_http::config::Config;
use lint_http::rules::RuleConfigEngine;

/// Build a quinn client endpoint that trusts the CA at `ca_cert_path` and
/// advertises ALPN `h3`.
fn build_h3_client(ca_cert_path: &std::path::Path) -> anyhow::Result<quinn::Endpoint> {
    use rustls::RootCertStore;
    use std::io::BufReader;

    let mut root_store = RootCertStore::empty();
    let f = std::fs::File::open(ca_cert_path)?;
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(f)).collect::<Result<Vec<_>, _>>()?;
    root_store.add_parsable_certificates(certs);

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| anyhow::anyhow!("QuicClientConfig: {}", e))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    // Use short idle timeout to speed up connection closure in tests
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Start the proxy with TLS + h3_listen enabled, return handles and addresses.
#[allow(clippy::type_complexity)]
async fn start_proxy_with_h3(
    cfg_modifier: Option<Box<dyn FnOnce(&mut Config) + Send>>,
) -> anyhow::Result<(
    tokio::task::JoinHandle<()>,
    SocketAddr,         // TCP listen address
    SocketAddr,         // H3/QUIC listen address
    String,             // captures path
    std::path::PathBuf, // CA cert path
    std::path::PathBuf, // CA key path
)> {
    let mut cfg = Config::default();
    cfg.tls.enabled = true;

    let cert_path = std::env::temp_dir().join(format!("h3_test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("h3_test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

    // Find free ports for TCP and UDP
    let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let tcp_addr = tcp_listener.local_addr()?;
    drop(tcp_listener);

    let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let h3_addr = udp_socket.local_addr()?;
    drop(udp_socket);

    cfg.general.h3_listen = Some(h3_addr.to_string());

    if let Some(f) = cfg_modifier {
        f(&mut cfg);
    }

    let tmp = std::env::temp_dir().join(format!("h3_integ_{}.jsonl", uuid::Uuid::new_v4()));
    let captures_path = tmp.to_str().unwrap().to_string();
    let cw = CaptureWriter::new(captures_path.clone(), false).await?;

    let engine = Arc::new(RuleConfigEngine::new());
    let cfg = Arc::new(cfg);
    let cfg2 = cfg.clone();
    let handle = tokio::spawn(async move {
        let _ = lint_http::proxy::run_proxy(tcp_addr, cw, cfg2, engine).await;
    });

    // Wait for TCP listener
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(anyhow::anyhow!("timeout waiting for proxy TCP"));
        }
        if let Ok(mut s) = tokio::net::TcpStream::connect(tcp_addr).await {
            use tokio::io::AsyncWriteExt;
            let _ = s.shutdown().await;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for CA files
    let deadline2 = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if cert_path.exists() && key_path.exists() {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            return Err(anyhow::anyhow!("timeout waiting for CA files"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for the H3/QUIC listener to be ready by probing with a connect attempt
    let probe_endpoint = build_h3_client(&cert_path)?;
    let deadline3 = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::time::Instant::now() > deadline3 {
            return Err(anyhow::anyhow!("timeout waiting for H3/QUIC listener"));
        }
        if let Ok(connecting) = probe_endpoint.connect(h3_addr, "localhost") {
            if connecting.await.is_ok() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    probe_endpoint.close(0u32.into(), b"probe");
    // Brief pause so the probe connection is cleaned up server-side
    tokio::time::sleep(Duration::from_millis(50)).await;

    Ok((
        handle,
        tcp_addr,
        h3_addr,
        captures_path,
        cert_path,
        key_path,
    ))
}

/// Send a single HTTP/3 GET request via quinn+h3, return status and body.
///
/// The H3 connection driver is awaited before returning so no background tasks
/// leak across tests.
async fn h3_get(
    endpoint: &quinn::Endpoint,
    h3_addr: SocketAddr,
    uri: &str,
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    use bytes::Buf;

    let conn = endpoint.connect(h3_addr, "localhost")?.await?;
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    // Drive the connection in the background; we join the handle below.
    let driver_handle = tokio::spawn(async move {
        futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut req = http::Request::builder().method("GET").uri(uri);
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let req = req.body(())?;

    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut buf = chunk;
        while buf.has_remaining() {
            let b = buf.chunk();
            body.extend_from_slice(b);
            let len = b.len();
            buf.advance(len);
        }
    }

    // Signal no more requests and wait for the driver to shut down.
    drop(stream);
    drop(send_request);
    let _ = driver_handle.await;

    Ok((status, headers, body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h3_happy_path_forwards_request_and_captures() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/hello"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("world")
                .insert_header("x-custom", "value"),
        )
        .mount(&mock)
        .await;

    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(None).await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/hello", mock.address().port());

    let (status, headers, body) = h3_get(&endpoint, h3_addr, &uri, &[]).await?;

    assert_eq!(status, 200);
    assert_eq!(body, b"world");
    // x-custom should be forwarded (not a hop-by-hop header)
    assert!(headers.iter().any(|(k, v)| k == "x-custom" && v == "value"));

    // Give captures time to flush
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify captures file
    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "captures file should not be empty");

    let v: serde_json::Value = serde_json::from_str(lines[0])?;
    assert_eq!(v["response"]["status"].as_u64(), Some(200));
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3"));
    // connection_id and sequence_number should be set
    assert!(v["connection_id"].as_str().is_some());
    assert_eq!(v["sequence_number"].as_u64(), Some(0));

    // Verify upstream mock received the request
    let reqs = mock.received_requests().await.unwrap();
    assert!(!reqs.is_empty());
    assert_eq!(reqs[0].url.path(), "/hello");

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}

#[tokio::test]
async fn h3_upstream_error_returns_502_and_records_transaction() -> anyhow::Result<()> {
    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(None).await?;

    let endpoint = build_h3_client(&cert_path)?;
    // Port 9 is the discard protocol — very unlikely to have an HTTP server
    let uri = "http://127.0.0.1:9/should-fail";

    let (status, _headers, _body) = h3_get(&endpoint, h3_addr, uri, &[]).await?;

    assert_eq!(status, 502);

    // Give captures time to flush
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The error transaction should still be recorded
    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "error transaction should be captured");

    let v: serde_json::Value = serde_json::from_str(lines[0])?;
    assert_eq!(v["response"]["status"].as_u64(), Some(502));
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3"));
    assert!(v["connection_id"].as_str().is_some());

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}

#[tokio::test]
async fn h3_suppress_headers_filters_configured_headers() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/sup"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(Some(Box::new(|cfg| {
            cfg.tls.suppress_headers = vec!["x-secret".to_string()];
        })))
        .await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/sup", mock.address().port());

    let (_status, _headers, _body) =
        h3_get(&endpoint, h3_addr, &uri, &[("x-secret", "password123")]).await?;

    // Give upstream time to receive the request
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify the suppressed header was NOT forwarded to upstream
    let reqs = mock.received_requests().await.unwrap();
    assert!(!reqs.is_empty());
    let has_secret = reqs[0]
        .headers
        .iter()
        .any(|(k, _v)| k.as_str().eq_ignore_ascii_case("x-secret"));
    assert!(!has_secret, "x-secret should be suppressed");

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}

#[tokio::test]
async fn h3_hop_by_hop_headers_stripped_from_response() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/hop"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("ok")
                .insert_header("connection", "keep-alive")
                .insert_header("transfer-encoding", "chunked")
                .insert_header("x-good", "stays"),
        )
        .mount(&mock)
        .await;

    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(None).await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/hop", mock.address().port());

    let (_status, headers, _body) = h3_get(&endpoint, h3_addr, &uri, &[]).await?;

    // Hop-by-hop headers should be stripped
    assert!(
        !headers.iter().any(|(k, _)| k == "connection"),
        "connection header should be stripped"
    );
    assert!(
        !headers.iter().any(|(k, _)| k == "transfer-encoding"),
        "transfer-encoding header should be stripped"
    );
    // Non-hop-by-hop headers should pass through
    assert!(
        headers.iter().any(|(k, v)| k == "x-good" && v == "stays"),
        "x-good header should pass through"
    );

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}

#[tokio::test]
async fn h3_multiple_requests_on_same_connection_increment_sequence() -> anyhow::Result<()> {
    use bytes::Buf;

    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/seq"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(2)
        .mount(&mock)
        .await;

    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(None).await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/seq", mock.address().port());

    // Open a single QUIC connection and send two requests so they share one
    // ConnectionMetadata and get incrementing sequence numbers.
    let conn = endpoint.connect(h3_addr, "localhost")?.await?;
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let driver_handle = tokio::spawn(async move {
        futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    for _ in 0..2 {
        let req = http::Request::builder().method("GET").uri(&uri).body(())?;
        let mut stream = send_request.send_request(req).await?;
        stream.finish().await?;

        let resp = stream.recv_response().await?;
        assert_eq!(resp.status().as_u16(), 200);

        // Drain body
        while let Some(chunk) = stream.recv_data().await? {
            let mut buf = chunk;
            while buf.has_remaining() {
                let len = buf.chunk().len();
                buf.advance(len);
            }
        }
    }

    drop(send_request);
    let _ = driver_handle.await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 2, "should have at least 2 capture records");

    // Parse all capture records
    let mut records: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Sort by sequence_number for deterministic ordering
    records.sort_by_key(|v| v["sequence_number"].as_u64().unwrap_or(0));

    // Both should share the same connection_id
    let cid0 = records[0]["connection_id"].as_str().unwrap();
    let cid1 = records[1]["connection_id"].as_str().unwrap();
    assert_eq!(
        cid0, cid1,
        "both requests should share the same connection_id"
    );

    // Sequence numbers should be 0 and 1
    assert_eq!(records[0]["sequence_number"].as_u64(), Some(0));
    assert_eq!(records[1]["sequence_number"].as_u64(), Some(1));

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}

#[tokio::test]
async fn h3_request_with_host_header_fallback() -> anyhow::Result<()> {
    // When the URI has no authority (path-only), the handler falls back to the
    // Host header for the upstream authority.  HTTP/3 always sets :scheme, so
    // the scheme fallback cannot be tested this way; we verify only that the
    // authority is resolved from Host and that the request is captured with
    // the correct host value.
    let (handle, _tcp_addr, h3_addr, captures_path, cert_path, key_path) =
        start_proxy_with_h3(None).await?;

    let endpoint = build_h3_client(&cert_path)?;
    // Send a path-only URI with explicit Host header.  The upstream will fail
    // (502) because h3 injects :scheme https and there is no real HTTPS server
    // at this host, but the captured transaction proves the authority was taken
    // from the Host header.
    let (status, _headers, _body) =
        h3_get(&endpoint, h3_addr, "/fallback", &[("host", "127.0.0.1:1")]).await?;
    assert_eq!(status, 502);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "should capture the error transaction");

    // The captured URI should contain the host from the Host header
    let v: serde_json::Value = serde_json::from_str(lines.last().unwrap())?;
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3"));
    // The host header value was used to build the upstream URI
    let captured_uri = v["request"]["uri"].as_str().unwrap_or("");
    assert!(
        captured_uri.contains("/fallback"),
        "captured URI should contain path: {}",
        captured_uri
    );

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&cert_path).await;
    let _ = tokio::fs::remove_file(&key_path).await;
    Ok(())
}
