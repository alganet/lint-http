// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration test for the HTTP/3 (QUIC) *upstream* leg (proxy -> origin).
//!
//! A client speaks plain HTTP/1.1 to the proxy; the proxy forwards to an
//! in-process HTTP/3 origin because that origin's authority is on the
//! `h3_upstream_authorities` allowlist. This exercises the P1 seam end to end:
//! the QUIC client endpoint, the request/response adaptation, capture parity
//! (the transaction records the origin leg as HTTP/3), and the RFC 9114 §4.2
//! field discipline (a connection-specific field is stripped before it reaches
//! the origin).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::TokioIo;

use lint_http::config::Config;

mod common;
use common::{start_run_proxy_and_wait, startup_timeout};

/// A self-signed test CA and a leaf certificate (IP SAN 127.0.0.1) signed by it.
struct TestPki {
    ca_pem: String,
    leaf_cert: rustls::pki_types::CertificateDer<'static>,
    leaf_key: rustls::pki_types::PrivateKeyDer<'static>,
}

/// Generate a throwaway CA and a leaf cert valid for 127.0.0.1, so the proxy's
/// H3 upstream client (configured to trust the CA) validates the origin's
/// endpoint certificate for its authority.
fn gen_test_pki() -> anyhow::Result<TestPki> {
    use rcgen::SanType;
    gen_test_pki_san(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
}

/// Like [`gen_test_pki`] but with a caller-chosen SAN, so a test can mint a leaf
/// that is *not* valid for 127.0.0.1 (to exercise the cert-for-origin gate).
fn gen_test_pki_san(san: rcgen::SanType) -> anyhow::Result<TestPki> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "lint-http upstream-h3 test CA");
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();

    let mut leaf_params = CertificateParams::new(Vec::new())?;
    leaf_params.subject_alt_names = vec![san];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "lint-http upstream-h3 test leaf");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    let leaf_cert_der = leaf_cert.der().clone();
    let leaf_key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();

    Ok(TestPki {
        ca_pem,
        leaf_cert: leaf_cert_der,
        leaf_key: leaf_key_der,
    })
}

/// Captured request headers the origin saw, for the field-discipline assertions.
type CapturedHeaders = Arc<Mutex<Option<Vec<(String, String)>>>>;

/// Build a QUIC server endpoint for the in-process H3 origin, using `pki`'s leaf
/// cert and ALPN `h3`.
fn h3_server_endpoint(pki: &TestPki, bind: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf_cert.clone()], pki.leaf_key.clone_key())?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow::anyhow!("origin QUIC server config: {e}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    Ok(quinn::Endpoint::server(server_config, bind)?)
}

/// Start an in-process HTTP/3 origin that replies `200` `"world"` with an
/// `x-origin: h3` header and records the request headers it received. Returns
/// its UDP address, the captured-headers handle, and the accept-loop task.
fn start_h3_origin(
    pki: &TestPki,
    bind: SocketAddr,
) -> anyhow::Result<(SocketAddr, CapturedHeaders, tokio::task::JoinHandle<()>)> {
    let endpoint = h3_server_endpoint(pki, bind)?;
    let addr = endpoint.local_addr()?;

    let captured: CapturedHeaders = Arc::new(Mutex::new(None));
    let captured_loop = captured.clone();
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let captured = captured_loop.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut h3 =
                    match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let captured = captured.clone();
                    tokio::spawn(async move {
                        if let Ok((req, mut stream)) = resolver.resolve_request().await {
                            let hs = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                                })
                                .collect();
                            *captured.lock().unwrap() = Some(hs);

                            let resp = http::Response::builder()
                                .status(200)
                                .header("x-origin", "h3")
                                .body(())
                                .unwrap();
                            let _ = stream.send_response(resp).await;
                            let _ = stream.send_data(Bytes::from_static(b"world")).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });

    Ok((addr, captured, handle))
}

/// Send one HTTP/1.1 request to the proxy (absolute origin authority via Host),
/// returning status, response headers, and body.
async fn proxy_get(
    proxy_addr: SocketAddr,
    origin_authority: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{origin_authority}{path}"))
        .header("host", origin_authority);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Empty::<Bytes>::new())?;

    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, headers, body))
}

async fn read_captures(path: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let deadline = std::time::Instant::now() + startup_timeout();
    loop {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let lines: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if !lines.is_empty() {
                return Ok(lines);
            }
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("capture not written within timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn upstream_h3_forwards_with_capture_parity_and_strips_connection_field() -> anyhow::Result<()>
{
    let pki = gen_test_pki()?;

    // Persist the CA PEM so the proxy can load it as an extra trust root.
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let (origin_addr, captured, origin_handle) = start_h3_origin(&pki, "127.0.0.1:0".parse()?)?;
    let origin_authority = origin_addr.to_string();

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![origin_authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // `keep-alive` is a connection-specific field (RFC 9114 §4.2) that must be
    // stripped before the H3 request; `x-forward-me` is an ordinary field that
    // must survive, proving parity with the H1/H2 forward.
    let (status, headers, body) = proxy_get(
        proxy_addr,
        &origin_authority,
        "/hello",
        &[("keep-alive", "timeout=5"), ("x-forward-me", "yes")],
    )
    .await?;

    assert_eq!(status, 200, "proxy should relay the origin's 200");
    assert_eq!(body, b"world");
    assert!(
        headers.iter().any(|(k, v)| k == "x-origin" && v == "h3"),
        "origin's x-origin header should reach the client: {headers:?}"
    );

    // The origin received the forwarded request: ordinary field kept, the
    // connection-specific field stripped.
    let origin_headers = captured
        .lock()
        .unwrap()
        .clone()
        .expect("origin should have recorded the forwarded request headers");
    assert!(
        origin_headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-forward-me") && v == "yes"),
        "x-forward-me should be forwarded to the H3 origin: {origin_headers:?}"
    );
    assert!(
        !origin_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("keep-alive")),
        "keep-alive (connection-specific, RFC 9114 §4.2) must be stripped: {origin_headers:?}"
    );

    // Capture parity: the transaction records the origin leg as HTTP/3 while the
    // client leg stays HTTP/1.1 (each hop's version recorded independently).
    let caps = read_captures(&captures_path).await?;
    let v = &caps[0];
    assert_eq!(v["response"]["status"].as_u64(), Some(200));
    assert_eq!(
        v["response"]["version"].as_str(),
        Some("HTTP/3"),
        "upstream (origin) leg should be recorded as HTTP/3"
    );
    assert_eq!(v["request"]["version"].as_str(), Some("HTTP/1.1"));

    // Cleanup
    proxy_handle.abort();
    origin_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_disabled_authority_uses_h1_path() -> anyhow::Result<()> {
    // An origin *not* on the allowlist takes the ordinary H1/H2 client. Use an
    // H1 wiremock origin and assert the recorded upstream version is HTTP/1.1,
    // confirming the H3 branch is gated by the allowlist.
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_string("h1"))
        .mount(&mock)
        .await;

    let mut cfg = Config::default();
    // H3 upstream is enabled but the mock's authority is not on the allowlist.
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec!["somewhere-else.example:443".to_string()];

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let mock_authority = format!("127.0.0.1:{}", mock.address().port());
    let (status, _headers, body) = proxy_get(proxy_addr, &mock_authority, "/plain", &[]).await?;
    assert_eq!(status, 200);
    assert_eq!(body, b"h1");

    let caps = read_captures(&captures_path).await?;
    let v = &caps[0];
    assert_eq!(
        v["response"]["version"].as_str(),
        Some("HTTP/1.1"),
        "non-allowlisted authority should use the H1/H2 client, not H3"
    );

    proxy_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    Ok(())
}

/// Send one HTTP/1.1 POST to the proxy, returning status and response body.
async fn proxy_post(
    proxy_addr: SocketAddr,
    origin_authority: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<(u16, Vec<u8>)> {
    let stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{origin_authority}{path}"))
        .header("host", origin_authority)
        .body(Full::new(Bytes::copy_from_slice(body)))?;
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, body))
}

#[tokio::test]
async fn upstream_h3_connect_failure_falls_back_to_h1() -> anyhow::Result<()> {
    // The allowlisted authority has an H1 origin (wiremock, TCP) but *no* H3
    // endpoint on the matching UDP port. The H3 attempt fails at connect
    // (pre-request), so the proxy falls back to H1/H2 and the request succeeds —
    // and the capture records the leg actually used as HTTP/1.1.
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/fb"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fell-back"))
        .mount(&mock)
        .await;

    let authority = format!("127.0.0.1:{}", mock.address().port());

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    // Keep the failed-connect wait short so the fall-back is prompt.
    cfg.general.h3_upstream_connect_timeout_ms = 1500;

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let (status, _headers, body) = proxy_get(proxy_addr, &authority, "/fb", &[]).await?;
    assert_eq!(status, 200, "the H1 fall-back should succeed");
    assert_eq!(body, b"fell-back");

    let caps = read_captures(&captures_path).await?;
    let v = &caps[0];
    assert_eq!(
        v["response"]["version"].as_str(),
        Some("HTTP/1.1"),
        "a fall-back records the leg actually used (H1), not H3"
    );

    proxy_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_non_idempotent_not_retried_after_midflight_failure() -> anyhow::Result<()> {
    // A POST (non-idempotent) whose H3 attempt fails *after* the handshake — the
    // origin accepts the connection and reads the request, then drops without
    // responding — must NOT be retried on H1/H2 (RFC 9110 §9.2.2). We prove it
    // by running a working H1 origin on the same authority's TCP port and
    // asserting it is never hit while the client gets a 502.
    use tokio::io::AsyncWriteExt;

    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    // Reserve a port that both the UDP (H3) origin and the TCP (H1) origin bind.
    let reserved = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = reserved.local_addr()?.port();
    drop(reserved);
    let authority = format!("127.0.0.1:{port}");
    let bind: SocketAddr = authority.parse()?;

    // H3 origin: completes the handshake, reads one request, then drops the
    // connection without responding — a mid-flight failure for the proxy.
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf_cert.clone()], pki.leaf_key.clone_key())?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow::anyhow!("origin QUIC server config: {e}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let h3_endpoint = quinn::Endpoint::server(server_config, bind)?;
    let h3_origin = tokio::spawn(async move {
        while let Some(incoming) = h3_endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                // Read one request, then return — dropping `h3` closes the
                // connection so the proxy's response read fails mid-flight.
                if let Ok(Some(resolver)) = h3.accept().await {
                    let _ = resolver.resolve_request().await;
                }
            });
        }
    });

    // H1 origin on the same TCP port: records every hit; would return 200 if the
    // proxy (incorrectly) fell back.
    let h1_hits = Arc::new(AtomicUsize::new(0));
    let h1_hits_srv = h1_hits.clone();
    let tcp = tokio::net::TcpListener::bind(bind).await?;
    let h1_origin = tokio::spawn(async move {
        while let Ok((mut sock, _)) = tcp.accept().await {
            h1_hits_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                    .await;
            });
        }
    });

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    cfg.general.h3_upstream_connect_timeout_ms = 3000;

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let (status, _body) = proxy_post(proxy_addr, &authority, "/x", b"payload").await?;
    assert_eq!(
        status, 502,
        "a mid-flight H3 failure of a non-idempotent method surfaces as 502"
    );

    // Give any (erroneous) fall-back a chance to land before asserting it didn't.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        h1_hits.load(Ordering::SeqCst),
        0,
        "a non-idempotent POST must not be retried on H1 after a mid-flight H3 failure"
    );

    proxy_handle.abort();
    h3_origin.abort();
    h1_origin.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

/// An H3 origin that completes the handshake, reads one request, then holds the
/// connection open **without ever responding** — so the proxy's response-head
/// read hits its response timeout (as opposed to erroring on a dropped
/// connection). Binds `bind` (UDP) and returns its accept-loop handle.
fn start_h3_origin_silent(
    pki: &TestPki,
    bind: SocketAddr,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let endpoint = h3_server_endpoint(pki, bind)?;
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                // Read the request but never send a response; keep both the
                // connection (`h3`) and the request stream alive by sleeping, so
                // the client's `recv_response` blocks until its timeout fires.
                if let Ok(Some(resolver)) = h3.accept().await {
                    if let Ok((_req, _stream)) = resolver.resolve_request().await {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });
    Ok(handle)
}

#[tokio::test]
async fn upstream_h3_slow_origin_idempotent_get_falls_back_to_h1() -> anyhow::Result<()> {
    // The H3 origin handshakes and reads the GET but never answers, so the proxy
    // hits its (short) response-head timeout. A GET is idempotent and bodyless,
    // so the request is replayable: the proxy falls back to an H1 origin on the
    // same authority's TCP port and the client gets a 200 — a slow-but-healthy
    // origin must not surface as a 502.
    use tokio::io::AsyncWriteExt;

    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let port = reserve_udp_port()?;
    let authority = format!("127.0.0.1:{port}");
    let bind: SocketAddr = authority.parse()?;

    let h3_origin = start_h3_origin_silent(&pki, bind)?;

    // H1 origin on the same TCP port: proves the fall-back landed.
    let h1_hits = Arc::new(AtomicUsize::new(0));
    let h1_hits_srv = h1_hits.clone();
    let tcp = tokio::net::TcpListener::bind(bind).await?;
    let h1_origin = tokio::spawn(async move {
        while let Ok((mut sock, _)) = tcp.accept().await {
            h1_hits_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfellback")
                    .await;
            });
        }
    });

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    // Handshake budget generous; response budget tiny so the timeout is prompt.
    cfg.general.h3_upstream_connect_timeout_ms = 3000;
    cfg.general.h3_upstream_response_timeout_ms = 300;

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let (status, _headers, body) = proxy_get(proxy_addr, &authority, "/slow", &[]).await?;
    assert_eq!(
        status, 200,
        "an idempotent GET should fall back to H1, not 502"
    );
    assert_eq!(body, b"fellback");
    assert!(
        h1_hits.load(Ordering::SeqCst) >= 1,
        "the fall-back should have reached the H1 origin"
    );

    let caps = read_captures(&captures_path).await?;
    let v = &caps[0];
    assert_eq!(
        v["response"]["version"].as_str(),
        Some("HTTP/1.1"),
        "a response-timeout fall-back records the leg actually used (H1)"
    );

    proxy_handle.abort();
    h3_origin.abort();
    h1_origin.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_slow_origin_non_idempotent_post_502s() -> anyhow::Result<()> {
    // Same silent H3 origin, but a POST carrying a body. The body is already in
    // flight (sent > 0) and the method is non-idempotent, so a response-timeout
    // is NOT replayable: the proxy must 502 rather than re-send to H1 (RFC 9110
    // §9.2.2). An H1 origin on the same port proves it is never hit.
    use tokio::io::AsyncWriteExt;

    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let port = reserve_udp_port()?;
    let authority = format!("127.0.0.1:{port}");
    let bind: SocketAddr = authority.parse()?;

    let h3_origin = start_h3_origin_silent(&pki, bind)?;

    let h1_hits = Arc::new(AtomicUsize::new(0));
    let h1_hits_srv = h1_hits.clone();
    let tcp = tokio::net::TcpListener::bind(bind).await?;
    let h1_origin = tokio::spawn(async move {
        while let Ok((mut sock, _)) = tcp.accept().await {
            h1_hits_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                    .await;
            });
        }
    });

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    cfg.general.h3_upstream_connect_timeout_ms = 3000;
    cfg.general.h3_upstream_response_timeout_ms = 300;

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let (status, _body) = proxy_post(proxy_addr, &authority, "/x", b"payload").await?;
    assert_eq!(
        status, 502,
        "a non-idempotent POST that times out mid-response is not replayable"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        h1_hits.load(Ordering::SeqCst),
        0,
        "a POST with a body must not be retried on H1 after a response timeout"
    );

    proxy_handle.abort();
    h3_origin.abort();
    h1_origin.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

/// An H3 origin that answers `401` the instant it sees a request, **without
/// reading the request body** — exercising the duplex path where the origin
/// responds (and resets the request stream) before the upload is drained.
fn start_h3_origin_early_response(
    pki: &TestPki,
    bind: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let endpoint = h3_server_endpoint(pki, bind)?;
    let addr = endpoint.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                            // Respond immediately, ignoring the request body.
                            let resp = http::Response::builder().status(401).body(()).unwrap();
                            let _ = stream.send_response(resp).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    Ok((addr, handle))
}

#[tokio::test]
async fn upstream_h3_origin_early_response_is_delivered_and_captured() -> anyhow::Result<()> {
    // The H3 origin answers 401 without draining the (sizeable) POST body. With
    // duplex send/recv the proxy observes that response concurrently with the
    // upload, delivers it to the client, and still commits the transaction —
    // proving the body pump handles an origin-reset stream without hanging the
    // capture or mis-recording the leg.
    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let (origin_addr, origin_handle) =
        start_h3_origin_early_response(&pki, "127.0.0.1:0".parse()?)?;
    let authority = origin_addr.to_string();

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    let big = vec![b'x'; 256 * 1024];
    let (status, _body) = proxy_post(proxy_addr, &authority, "/gate", &big).await?;
    assert_eq!(status, 401, "the early origin response reaches the client");

    let caps = read_captures(&captures_path).await?;
    let v = &caps[0];
    assert_eq!(v["response"]["status"].as_u64(), Some(401));
    assert_eq!(
        v["response"]["version"].as_str(),
        Some("HTTP/3"),
        "the leg is recorded as HTTP/3 even though the origin responded early"
    );

    proxy_handle.abort();
    origin_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_early_response_to_large_upload_commits_without_hanging() -> anyhow::Result<()>
{
    // Regression for the duplex body pump: the origin answers 401 without reading
    // an upload *larger than the QUIC flow-control window*, so the pump parks in
    // `send_data`. The response must still reach the client AND the transaction
    // must still commit — proving the pump is aborted (dropping the request tee,
    // firing `body_done`) when the response body drops, rather than parking
    // forever and leaking the capture. A timeout guards against the regression
    // hanging the whole suite.
    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_upstream_h3_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let (origin_addr, origin_handle) =
        start_h3_origin_early_response(&pki, "127.0.0.1:0".parse()?)?;
    let authority = origin_addr.to_string();

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];

    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // 16 MiB comfortably exceeds quinn's default per-stream receive window, so the
    // pump parks once the origin (which never reads) stops accepting bytes.
    let big = vec![b'x'; 16 * 1024 * 1024];
    let (status, _body) = tokio::time::timeout(
        Duration::from_secs(20),
        proxy_post(proxy_addr, &authority, "/gate", &big),
    )
    .await
    .map_err(|_| anyhow::anyhow!("proxy_post hung — the parked pump was not aborted"))??;
    assert_eq!(status, 401, "the early origin response reaches the client");

    // The capture being written at all proves `body_done` fired despite the
    // parked pump (read_captures has its own startup timeout).
    let caps = read_captures(&captures_path).await?;
    assert_eq!(caps[0]["response"]["status"].as_u64(), Some(401));

    proxy_handle.abort();
    origin_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

/// Reserve an ephemeral UDP port, then release it so a caller can bind it.
fn reserve_udp_port() -> anyhow::Result<u16> {
    let s = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = s.local_addr()?.port();
    drop(s);
    Ok(port)
}

#[tokio::test]
async fn upstream_h3_discovered_via_alt_svc_is_used_on_next_request() -> anyhow::Result<()> {
    // An H1 origin advertises H3 via Alt-Svc. The first request goes H1 (nothing
    // discovered yet) and populates the discovery cache; the second request is
    // routed over H3 to the advertised endpoint.
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_disc_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    // The advertised H3 endpoint (serves "world" over H3), bound to a known port.
    let port_e = reserve_udp_port()?;
    let (_e_addr, _captured, e_handle) =
        start_h3_origin(&pki, format!("127.0.0.1:{port_e}").parse()?)?;

    // The H1 origin advertises `h3=":port_e"` (same host, the H3 port).
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/d"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("h1")
                .insert_header("alt-svc", format!("h3=\":{port_e}\"; ma=3600").as_str()),
        )
        .mount(&mock)
        .await;
    let authority = format!("127.0.0.1:{}", mock.address().port());

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    // No allowlist: H3 is reached purely through Alt-Svc discovery.
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // First request: H1 (wiremock), which advertises Alt-Svc.
    let (s1, _h1, b1) = proxy_get(proxy_addr, &authority, "/d", &[]).await?;
    assert_eq!(s1, 200);
    assert_eq!(b1, b"h1", "first request is served by the H1 origin");

    // Second request: discovered → H3 endpoint, which answers "world".
    let (s2, _h2, b2) = proxy_get(proxy_addr, &authority, "/d", &[]).await?;
    assert_eq!(s2, 200);
    assert_eq!(
        b2, b"world",
        "second request is served over H3 (discovered)"
    );

    let caps = read_captures(&captures_path).await?;
    let versions: Vec<&str> = caps
        .iter()
        .filter_map(|v| v["response"]["version"].as_str())
        .collect();
    assert!(
        versions.contains(&"HTTP/3"),
        "a request should have been forwarded over H3 after discovery: {versions:?}"
    );

    proxy_handle.abort();
    e_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_discovered_endpoint_with_wrong_cert_is_not_used() -> anyhow::Result<()> {
    // The discovered H3 endpoint presents a (trusted-CA) certificate that is
    // valid for "wrong.example", NOT for the origin's 127.0.0.1 authority. Per
    // RFC 7838 §2.1 the mapping must not be used: the H3 handshake fails the
    // name check and the proxy falls back to H1, leaving the H3 endpoint unused.
    use rcgen::SanType;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Leaf valid for "wrong.example" only.
    let pki = gen_test_pki_san(SanType::DnsName("wrong.example".try_into()?))?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_disc_badca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let port_e = reserve_udp_port()?;
    let (_e_addr, e_captured, e_handle) =
        start_h3_origin(&pki, format!("127.0.0.1:{port_e}").parse()?)?;

    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/w"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("h1-origin")
                .insert_header("alt-svc", format!("h3=\":{port_e}\"; ma=3600").as_str()),
        )
        .mount(&mock)
        .await;
    let authority = format!("127.0.0.1:{}", mock.address().port());

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    cfg.general.h3_upstream_connect_timeout_ms = 2000;
    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // First request populates discovery; second would use H3 but the cert is
    // not valid for the origin, so it falls back to H1.
    let (s1, _h1, _b1) = proxy_get(proxy_addr, &authority, "/w", &[]).await?;
    assert_eq!(s1, 200);
    let (s2, _h2, b2) = proxy_get(proxy_addr, &authority, "/w", &[]).await?;
    assert_eq!(s2, 200, "the request still succeeds by falling back to H1");
    assert_eq!(
        b2, b"h1-origin",
        "served by the H1 origin, not the H3 endpoint"
    );

    // The H3 endpoint never served a request: its cert failed the origin-name
    // check during the handshake, before any request was sent.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        e_captured.lock().unwrap().is_none(),
        "an endpoint whose cert is not valid for the origin must not be used"
    );

    proxy_handle.abort();
    e_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

/// An H3 origin that counts accepted QUIC connections and serves `200`/"world"
/// for every request stream (multiplexed), so a test can assert that pooling
/// reuses one connection across requests.
fn start_h3_origin_counting(
    pki: &TestPki,
    bind: SocketAddr,
) -> anyhow::Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
    let endpoint = h3_server_endpoint(pki, bind)?;
    let addr = endpoint.local_addr()?;
    let conns = Arc::new(AtomicUsize::new(0));
    let conns_loop = conns.clone();
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            conns_loop.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                            let resp = http::Response::builder().status(200).body(()).unwrap();
                            let _ = stream.send_response(resp).await;
                            let _ = stream.send_data(Bytes::from_static(b"world")).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    Ok((addr, conns, handle))
}

/// An H3 origin that counts accepted connections, serves exactly one request per
/// connection, then sends GOAWAY (via `shutdown`) refusing further streams — so
/// a reused pooled connection is refused and the proxy must retry on a fresh one.
fn start_h3_origin_goaway(
    pki: &TestPki,
    bind: SocketAddr,
) -> anyhow::Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
    let endpoint = h3_server_endpoint(pki, bind)?;
    let addr = endpoint.local_addr()?;
    let conns = Arc::new(AtomicUsize::new(0));
    let conns_loop = conns.clone();
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            conns_loop.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                if let Ok(Some(resolver)) = h3.accept().await {
                    if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from_static(b"world")).await;
                        let _ = stream.finish().await;
                    }
                }
                // GOAWAY allowing the request just served (grace = 1) but refusing
                // any further stream; keep the connection alive briefly so it is
                // the GOAWAY — not a connection close — that refuses the retry.
                let _ = h3.shutdown(1).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            });
        }
    });
    Ok((addr, conns, handle))
}

#[tokio::test]
async fn upstream_h3_pool_reuses_one_connection_across_requests() -> anyhow::Result<()> {
    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_pool_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let (origin_addr, conns, origin_handle) =
        start_h3_origin_counting(&pki, "127.0.0.1:0".parse()?)?;
    let authority = origin_addr.to_string();

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // Three sequential requests to the same origin should share one pooled
    // QUIC connection.
    for _ in 0..3 {
        let (status, _h, body) = proxy_get(proxy_addr, &authority, "/p", &[]).await?;
        assert_eq!(status, 200);
        assert_eq!(body, b"world");
    }

    assert_eq!(
        conns.load(Ordering::SeqCst),
        1,
        "three requests should reuse a single pooled H3 connection"
    );

    proxy_handle.abort();
    origin_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}

#[tokio::test]
async fn upstream_h3_goaway_refused_request_is_retried_on_fresh_connection() -> anyhow::Result<()> {
    let pki = gen_test_pki()?;
    let ca_pem_path =
        std::env::temp_dir().join(format!("lint_goaway_ca_{}.pem", uuid::Uuid::new_v4()));
    tokio::fs::write(&ca_pem_path, pki.ca_pem.as_bytes()).await?;

    let (origin_addr, conns, origin_handle) = start_h3_origin_goaway(&pki, "127.0.0.1:0".parse()?)?;
    let authority = origin_addr.to_string();

    let mut cfg = Config::default();
    cfg.general.h3_upstream_enabled = true;
    cfg.general.h3_upstream_authorities = vec![authority.clone()];
    cfg.general.h3_upstream_extra_ca_certs = vec![ca_pem_path.to_string_lossy().to_string()];
    let (proxy_handle, proxy_addr, captures_path) = start_run_proxy_and_wait(cfg).await?;

    // First request opens and pools a connection; the origin GOAWAYs it after
    // serving. The second request reuses the pooled connection, is refused, and
    // must be retried on a fresh connection — so both succeed and the origin
    // accepts a second connection.
    let (s1, _h1, b1) = proxy_get(proxy_addr, &authority, "/g", &[]).await?;
    assert_eq!(s1, 200);
    assert_eq!(b1, b"world");

    // Let the origin's GOAWAY reach the pooled connection before reusing it.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (s2, _h2, b2) = proxy_get(proxy_addr, &authority, "/g", &[]).await?;
    assert_eq!(
        s2, 200,
        "the GOAWAY-refused request is retried on a fresh connection"
    );
    assert_eq!(b2, b"world");

    assert!(
        conns.load(Ordering::SeqCst) >= 2,
        "a second connection is opened to retry the refused request, got {}",
        conns.load(Ordering::SeqCst)
    );

    proxy_handle.abort();
    origin_handle.abort();
    let _ = tokio::fs::remove_file(&captures_path).await;
    let _ = tokio::fs::remove_file(&ca_pem_path).await;
    Ok(())
}
