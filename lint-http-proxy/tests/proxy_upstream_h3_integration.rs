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

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
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
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
        PKCS_ECDSA_P256_SHA256,
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
    leaf_params.subject_alt_names =
        vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
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

/// Start an in-process HTTP/3 origin that replies `200` `"world"` with an
/// `x-origin: h3` header and records the request headers it received. Returns
/// its UDP address, the captured-headers handle, and the accept-loop task.
fn start_h3_origin(
    pki: &TestPki,
) -> anyhow::Result<(SocketAddr, CapturedHeaders, tokio::task::JoinHandle<()>)> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf_cert.clone()], pki.leaf_key.clone_key())?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow::anyhow!("origin QUIC server config: {e}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
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

    let (origin_addr, captured, origin_handle) = start_h3_origin(&pki)?;
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
