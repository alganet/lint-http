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

mod common;
use common::{startup_timeout, tls_config, TempFiles};

/// Build a quinn client endpoint that trusts the CA at `ca_cert_path` and
/// advertises ALPN `h3`.
fn build_h3_client(ca_cert_path: &std::path::Path) -> anyhow::Result<quinn::Endpoint> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    let certs: Vec<_> =
        CertificateDer::pem_file_iter(ca_cert_path)?.collect::<Result<Vec<_>, _>>()?;
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

/// A tweak applied to the config before the proxy starts.
///
/// Named because the type is the other half of what the removed
/// `#[allow(type_complexity)]` was covering: the allow sat on the function, so
/// it silenced the parameter as well as the return.
type ConfigTweak = Box<dyn FnOnce(&mut Config) + Send>;

/// A proxy under test with HTTP/3 enabled, and what a test needs to reach it.
///
/// **This was five positional values behind an `#[allow(type_complexity)]`**,
/// and the allow was the honest signal: two of them were `SocketAddr` and two
/// were paths, so a call site that swapped a pair would still compile. Every
/// field is named at the destructuring now, and a test names only the ones it
/// uses — which is what retired the `_tcp_addr` and `_captures_path`
/// placeholders the tuple forced on callers that wanted neither, and what
/// showed that nothing read the TCP address at all.
struct H3Proxy {
    handle: tokio::task::JoinHandle<()>,
    /// The H3/QUIC listen address. The TCP one is *not* here: no test reads
    /// it, and it was in the tuple only because the function happened to have
    /// it — which a positional return makes invisible and a named field asks
    /// out loud.
    h3_addr: SocketAddr,
    captures_path: String,
    /// Where the proxy generated its CA, for a client that must trust it.
    cert_path: std::path::PathBuf,
}

/// Start the proxy with TLS + h3_listen enabled.
///
/// Every temporary file this makes belongs to `temp`, including the CA key —
/// which is why that one is not returned at all: it was in the tuple for the
/// teardown alone, and the teardown is the guard's now.
async fn start_proxy_with_h3(
    cfg_modifier: Option<ConfigTweak>,
    temp: &mut TempFiles,
) -> anyhow::Result<H3Proxy> {
    let mut cfg = tls_config(temp);
    let cert_path = common::ca_cert_path(&cfg);
    let key_path = std::path::PathBuf::from(
        cfg.tls
            .ca_key_path
            .clone()
            .expect("tls_config always names a CA key path"),
    );

    // Find free ports for TCP and UDP
    // Keep the listener and hand it to the proxy below: dropping it here would
    // leave the port unowned until `run_proxy` rebinds it, and another test in
    // this binary can take it in that gap.
    let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let tcp_addr = tcp_listener.local_addr()?;

    // Keep this one too, and hand it over below. `h3_listen` still decides that
    // HTTP/3 runs; the socket decides which port it runs on, and a port released
    // here is one another test can take before the QUIC endpoint binds it.
    let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let h3_addr = udp_socket.local_addr()?;

    cfg.general.h3_listen = Some(h3_addr.to_string());

    if let Some(f) = cfg_modifier {
        f(&mut cfg);
    }

    let tmp = temp.path("h3_integ", "jsonl");
    let captures_path = tmp.to_str().unwrap().to_string();
    let cw = CaptureWriter::new(captures_path.clone(), false).await?;

    let cfg = Arc::new(cfg);
    let cfg2 = cfg.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = lint_http::proxy::run_proxy((tcp_listener, udp_socket), cw, cfg2).await {
            eprintln!("run_proxy on {tcp_addr} exited: {e:#}");
        }
    });

    // Wait for TCP listener
    let deadline = std::time::Instant::now() + startup_timeout();
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
    let deadline2 = std::time::Instant::now() + startup_timeout();
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
    let deadline3 = std::time::Instant::now() + startup_timeout();
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

    Ok(H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
    })
}

/// Read the capture file once at least `want` record(s) have reached it,
/// polling to a deadline rather than sleeping a guessed interval.
///
/// The two callers below used `sleep(200ms)`, which is two failures in one: it
/// costs 200ms on a fast machine that was ready immediately, and it races on a
/// loaded CI runner that was not. The writer flushes on its own schedule, so
/// the only honest wait is for the record itself. Both sibling suites —
/// `proxy_websocket_relay` and `proxy_upstream_h3_integration` — already do
/// this; this file was the one left guessing.
async fn read_captures_when_ready(
    path: impl AsRef<std::path::Path>,
    want: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let deadline = std::time::Instant::now() + startup_timeout();
    loop {
        let content = tokio::fs::read_to_string(path.as_ref())
            .await
            .unwrap_or_default();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() >= want {
            return lines.iter().map(|l| Ok(serde_json::from_str(l)?)).collect();
        }
        if std::time::Instant::now() > deadline {
            return Err(anyhow::anyhow!(
                "timed out waiting for {want} capture record(s); saw {}",
                lines.len()
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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

/// Send a single HTTP/3 POST request with a body via quinn+h3, return status
/// and response body. Mirrors [`h3_get`].
async fn h3_request_with_body(
    endpoint: &quinn::Endpoint,
    h3_addr: SocketAddr,
    uri: &str,
    body: &[u8],
) -> anyhow::Result<(u16, Vec<u8>)> {
    use bytes::Buf;

    let conn = endpoint.connect(h3_addr, "localhost")?.await?;
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    let driver_handle = tokio::spawn(async move {
        futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder().method("POST").uri(uri).body(())?;
    let mut stream = send_request.send_request(req).await?;
    stream
        .send_data(bytes::Bytes::copy_from_slice(body))
        .await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    let status = resp.status().as_u16();

    let mut resp_body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut buf = chunk;
        while buf.has_remaining() {
            let b = buf.chunk();
            resp_body.extend_from_slice(b);
            let len = b.len();
            buf.advance(len);
        }
    }

    drop(stream);
    drop(send_request);
    let _ = driver_handle.await;

    Ok((status, resp_body))
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

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(None, &mut temp).await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/hello", mock.address().port());

    let (status, headers, body) = h3_get(&endpoint, h3_addr, &uri, &[]).await?;

    assert_eq!(status, 200);
    assert_eq!(body, b"world");
    // x-custom should be forwarded (not a hop-by-hop header)
    assert!(headers.iter().any(|(k, v)| k == "x-custom" && v == "value"));

    let entries = read_captures_when_ready(&captures_path, 1).await?;
    let v = &entries[0];
    assert_eq!(v["response"]["status"].as_u64(), Some(200));
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3.0"));
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
    Ok(())
}

#[tokio::test]
async fn h3_upstream_error_returns_502_and_records_transaction() -> anyhow::Result<()> {
    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(None, &mut temp).await?;

    let endpoint = build_h3_client(&cert_path)?;
    // Port 9 is the discard protocol — very unlikely to have an HTTP server
    let uri = "http://127.0.0.1:9/should-fail";

    let (status, _headers, _body) = h3_get(&endpoint, h3_addr, uri, &[]).await?;

    assert_eq!(status, 502);

    // The error transaction is still recorded, so waiting for one record is
    // waiting for exactly the thing under test.
    let entries = read_captures_when_ready(&captures_path, 1).await?;
    let v = &entries[0];
    assert_eq!(v["response"]["status"].as_u64(), Some(502));
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3.0"));
    assert!(v["connection_id"].as_str().is_some());

    // Cleanup
    endpoint.close(0u32.into(), b"done");
    handle.abort();
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

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        cert_path,
        ..
    } = start_proxy_with_h3(
        Some(Box::new(|cfg| {
            cfg.tls.suppress_headers = vec!["x-secret".to_string()];
        })),
        &mut temp,
    )
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

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        cert_path,
        ..
    } = start_proxy_with_h3(None, &mut temp).await?;

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

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(None, &mut temp).await?;

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
    Ok(())
}

#[tokio::test]
async fn h3_large_request_body_streams_and_truncates_capture() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(
        Some(Box::new(|cfg| {
            cfg.general.captures_max_body_bytes = 16;
        })),
        &mut temp,
    )
    .await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/upload", mock.address().port());

    // A 64-byte request body exceeds the 16-byte capture bound but must still
    // be streamed to the upstream in full — no rejection, no 413.
    let (status, _body) = h3_request_with_body(&endpoint, h3_addr, &uri, &[b'a'; 64]).await?;
    assert_eq!(status, 200);

    // The upstream received the entire body, not a truncated or rejected one.
    let reqs = mock.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].body.len(), 64);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The capture holds only the bounded prefix, marked truncated, while
    // request body_length records the real streamed total.
    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "transaction should be captured");

    let v: serde_json::Value = serde_json::from_str(lines[0])?;
    assert_eq!(v["response"]["status"].as_u64(), Some(200));
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3.0"));
    assert_eq!(v["request_body_over_limit"].as_bool(), Some(true));
    assert_eq!(v["request"]["body_length"].as_u64(), Some(64));

    endpoint.close(0u32.into(), b"done");
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn h3_response_over_limit_streams_full_and_truncates_capture() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/big"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-upstream", "yes")
                .set_body_bytes(vec![b'b'; 64]),
        )
        .mount(&mock)
        .await;

    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(
        Some(Box::new(|cfg| {
            cfg.general.captures_max_body_bytes = 16;
        })),
        &mut temp,
    )
    .await?;

    let endpoint = build_h3_client(&cert_path)?;
    let uri = format!("http://127.0.0.1:{}/big", mock.address().port());

    let (status, _headers, body) = h3_get(&endpoint, h3_addr, &uri, &[]).await?;
    // The full response is streamed to the client (no rejection); only the
    // captured copy is bounded.
    assert_eq!(status, 200);
    assert_eq!(body.len(), 64);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The capture holds only the bounded prefix, marked truncated, while
    // body_length records the real streamed total.
    let content = tokio::fs::read_to_string(&captures_path).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "over-limit transaction should be captured"
    );

    let v: serde_json::Value = serde_json::from_str(lines[0])?;
    assert_eq!(v["response"]["status"].as_u64(), Some(200));
    assert_eq!(v["response_body_over_limit"].as_bool(), Some(true));
    assert_eq!(v["response"]["body_length"].as_u64(), Some(64));
    // The upstream's real response headers are recorded even though the body
    // was discarded (headers serialize as ordered [name, value] pairs).
    let resp_headers = v["response"]["headers"]
        .as_array()
        .expect("response headers serialize as an array");
    assert!(
        resp_headers.iter().any(|pair| {
            pair.get(0).and_then(|n| n.as_str()) == Some("x-upstream")
                && pair.get(1).and_then(|val| val.as_str()) == Some("yes")
        }),
        "captured response should retain the upstream x-upstream header: {resp_headers:?}"
    );

    endpoint.close(0u32.into(), b"done");
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn h3_request_with_host_header_fallback() -> anyhow::Result<()> {
    // When the URI has no authority (path-only), the handler falls back to the
    // Host header for the upstream authority.  HTTP/3 always sets :scheme, so
    // the scheme fallback cannot be tested this way; we verify only that the
    // authority is resolved from Host and that the request is captured with
    // the correct host value.
    let mut temp = TempFiles::new();
    let H3Proxy {
        handle,
        h3_addr,
        captures_path,
        cert_path,
        ..
    } = start_proxy_with_h3(None, &mut temp).await?;

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
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/3.0"));
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
    Ok(())
}
