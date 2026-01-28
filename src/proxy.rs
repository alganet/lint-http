// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP proxy server implementation with request forwarding and capture.

use crate::capture::CaptureWriter;
use crate::config::Config;
use crate::lint;

use crate::ca::CertificateAuthority;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper::{service::service_fn, Method, Request, Response, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{error, info, trace};

type ServiceFuture =
    Pin<Box<dyn Future<Output = Result<Response<BoxBody<Bytes, Infallible>>, Infallible>> + Send>>;

// RFC 7230 Section 6.1: Hop-by-hop headers must not be forwarded by proxies.
static HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

// Convert hyper::Version into the textual HTTP-version token used in start/status lines.
fn format_http_version(v: hyper::Version) -> String {
    match v {
        hyper::Version::HTTP_09 => "HTTP/0.9".to_string(),
        hyper::Version::HTTP_10 => "HTTP/1.0".to_string(),
        hyper::Version::HTTP_11 => "HTTP/1.1".to_string(),
        hyper::Version::HTTP_2 => "HTTP/2.0".to_string(),
        _ => "HTTP/1.1".to_string(),
    }
}

#[cfg(test)]
mod test_format_http_version {
    use super::*;
    use hyper::Version;
    use rstest::rstest;

    #[rstest]
    #[case(Version::HTTP_09, "HTTP/0.9")]
    #[case(Version::HTTP_10, "HTTP/1.0")]
    #[case(Version::HTTP_11, "HTTP/1.1")]
    #[case(Version::HTTP_2, "HTTP/2.0")]
    fn format_http_version_cases(#[case] ver: Version, #[case] expected: &str) {
        assert_eq!(format_http_version(ver), expected.to_string());
    }
}

#[derive(Debug)]
struct AlwaysResolves(Arc<CertifiedKey>);

impl ResolvesServerCert for AlwaysResolves {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Shared {
    client: LegacyClient<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<bytes::Bytes>,
    >,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    state: Arc<crate::state::StateStore>,
    ca: Option<Arc<CertificateAuthority>>,
    engine: Arc<crate::rules::RuleConfigEngine>,
}

pub async fn run_proxy(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    engine: Arc<crate::rules::RuleConfigEngine>,
) -> anyhow::Result<()> {
    // Default behavior: no accept limit (runs forever)
    run_proxy_with_limit(listen, captures, cfg, engine, None).await
}

/// Testable variant of `run_proxy` that accepts an optional `accept_limit`.
/// When `accept_limit` is `Some(n)`, the accept loop will accept `n` connections
/// and then return after accepting the Nth connection. Connection handlers are
/// spawned asynchronously and may still be running when this function returns,
/// allowing tests to deterministically bound how many connections are accepted.
pub async fn run_proxy_with_limit(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    engine: Arc<crate::rules::RuleConfigEngine>,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: LegacyClient<_, http_body_util::Full<bytes::Bytes>> =
        LegacyClient::builder(TokioExecutor::new()).build(https);

    let ca = if cfg.tls.enabled {
        let cert_path = cfg.tls.ca_cert_path.as_deref().unwrap_or("ca.crt");
        let key_path = cfg.tls.ca_key_path.as_deref().unwrap_or("ca.key");
        Some(
            CertificateAuthority::load_or_generate(
                std::path::Path::new(cert_path),
                std::path::Path::new(key_path),
            )
            .await?,
        )
    } else {
        None
    };

    let ttl = cfg.general.ttl_seconds;
    let state = Arc::new(crate::state::StateStore::new(ttl));

    // Seed state from captures file if enabled
    if cfg.general.captures_seed {
        match crate::capture::load_captures(&cfg.general.captures).await {
            Ok(records) => {
                let count = records.len();
                for record in &records {
                    state.seed_from_transaction(record);
                }
                info!(count, "seeded state from captures");
            }
            Err(e) => {
                // Log warning but don't fail startup
                tracing::warn!(error = %e, "failed to load captures for seeding");
            }
        }
    }

    // Spawn background cleanup task
    let state_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            state_cleanup.cleanup_expired();
        }
    });

    let shared = Arc::new(Shared {
        client,
        captures,
        cfg,
        state,
        ca,
        engine,
    });

    // Use a manual TcpListener accept loop to preserve the remote address and
    // avoid relying on the removed `make_service_fn` helper in hyper v1.
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "listening");

    let executor = TokioExecutor::new();
    let server_builder = AutoConnBuilder::new(executor);

    // Accept loop with optional limit
    let mut remaining = accept_limit;
    loop {
        // If we're limited and have reached zero, stop accepting
        if let Some(0) = remaining {
            break;
        }

        let (stream, remote_addr) = listener.accept().await?;

        // Decrement remaining if present
        if let Some(ref mut n) = remaining {
            *n -= 1;
        }

        let shared = shared.clone();
        let builder_clone = server_builder.clone();
        tokio::spawn(async move {
            let conn_metadata = Arc::new(crate::connection::ConnectionMetadata::new(remote_addr));
            let service = service_fn(move |req: Request<Incoming>| {
                let shared = shared.clone();
                let conn_metadata = conn_metadata.clone();
                let fut: ServiceFuture = Box::pin(async move {
                    handle_request(
                        req,
                        shared.clone(),
                        conn_metadata.clone(),
                        hyper::http::uri::Scheme::HTTP,
                    )
                    .await
                });
                fut
            });

            let io = TokioIo::new(stream);
            if let Err(e) = builder_clone
                .serve_connection_with_upgrades(io, service)
                .await
            {
                error!(%e, "connection error");
            }
        });
    }

    Ok(())
}

async fn handle_request<B>(
    req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() == Method::CONNECT {
        if shared.ca.is_some() {
            let uri = req.uri().clone();
            let shared = shared.clone();
            let conn_metadata = conn_metadata.clone();

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = handle_connect(upgraded, uri, shared, conn_metadata).await {
                            error!("connect error: {}", e);
                        }
                    }
                    Err(e) => error!("upgrade error for {}: {}", uri, e),
                }
            });
            return Ok(Response::new(Full::new(Bytes::new()).boxed()));
        } else {
            return Ok(Response::builder()
                .status(405)
                .body(Full::new(Bytes::from("CONNECT not supported (TLS disabled)")).boxed())
                .unwrap_or_else(|e| {
                    error!("failed to build 405 response: {}", e);
                    Response::new(
                        Full::new(Bytes::from("CONNECT not supported (TLS disabled)")).boxed(),
                    )
                }));
        }
    }

    // Serve CA certificate
    if req.uri().path() == "/_lint_http/cert" && req.method() == Method::GET {
        if let Some(ca) = &shared.ca {
            let pem = ca.get_ca_cert_pem();
            return Ok(Response::builder()
                .header("Content-Type", "application/x-x509-ca-cert")
                .header(
                    "Content-Disposition",
                    "attachment; filename=\"lint-http-ca.crt\"",
                )
                .body(Full::new(Bytes::from(pem.clone())).boxed())
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(pem.clone())).boxed())));
        } else {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("TLS not enabled")).boxed())
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("TLS not enabled")).boxed())
                }));
        }
    }

    handle_http_logic(req, shared, conn_metadata, scheme).await
}

async fn handle_inner_request<B>(
    req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() == Method::CONNECT {
        return Ok(Response::builder()
            .status(405)
            .body(Full::new(Bytes::from("Nested CONNECT not supported")).boxed())
            .unwrap_or_else(|_| {
                Response::new(Full::new(Bytes::from("Nested CONNECT not supported")).boxed())
            }));
    }
    handle_http_logic(req, shared, conn_metadata, scheme).await
}

async fn handle_http_logic<B>(
    req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    #[allow(clippy::too_many_arguments)]
    async fn build_and_write_transaction(
        captures: &CaptureWriter,
        client_id: &crate::state::ClientIdentifier,
        method: &str,
        uri_str: &str,
        req_headers: &hyper::HeaderMap<hyper::header::HeaderValue>,
        req_version: String,
        status: u16,
        response_headers: Option<hyper::HeaderMap<hyper::header::HeaderValue>>,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let mut tx = crate::http_transaction::HttpTransaction::new(
            client_id.clone(),
            method.to_string(),
            uri_str.to_string(),
        );
        tx.request.headers = req_headers.clone();
        tx.request.version = req_version;
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: response_headers.unwrap_or_default(),
            body_length: None,
        });
        tx.timing = crate::http_transaction::TimingInfo { duration_ms };
        captures.write_transaction(&tx).await?;
        Ok(())
    }
    let started = Instant::now();

    let uri = if req.uri().scheme().is_some() {
        req.uri().clone()
    } else {
        let host = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let s = format!("{}://{}{}", scheme, host, path);
        s.parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("http://localhost/"))
    };

    let mut builder = Request::builder().method(req.method()).uri(uri.clone());
    for (name, value) in req.headers().iter() {
        if !shared
            .cfg
            .tls
            .suppress_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name.as_str()))
        {
            builder = builder.header(name, value);
        }
    }

    let method = req.method().clone();
    let uri_str = req.uri().to_string();
    let req_headers = req.headers().clone();

    let client_ip = conn_metadata.remote_addr.ip();
    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let client_id = crate::state::ClientIdentifier::new(client_ip, user_agent);

    // Capture request version before moving `req` into body
    let req_version = format_http_version(req.version());
    let body = req.into_body();
    let captures = &shared.captures;

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
            error!("failed to collect request body: {}", boxed);
            let resp = Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("request body collect error")).boxed())
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("request body collect error")).boxed())
                });
            let duration = started.elapsed().as_millis() as u64;
            let _ = build_and_write_transaction(
                captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                req_version.clone(),
                500,
                None,
                duration,
            )
            .await;
            return Ok(resp);
        }
    };

    let upstream_req = match builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to build upstream request: {}", e);
            let body = Full::new(Bytes::from(format!("request build error: {}", e))).boxed();
            let resp = Response::builder()
                .status(500)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("internal error")).boxed())
                });
            // record a failed capture with 500
            let duration = started.elapsed().as_millis() as u64;
            let _ = build_and_write_transaction(
                captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                req_version.clone(),
                500,
                None,
                duration,
            )
            .await;
            return Ok(resp);
        }
    };
    let resp = match shared.client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            let body = Full::new(Bytes::from(format!("upstream error: {}", e))).boxed();
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            let duration = started.elapsed().as_millis() as u64;
            let _ = build_and_write_transaction(
                captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                req_version.clone(),
                502,
                None,
                duration,
            )
            .await;
            return Ok(resp);
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    // Capture the upstream response version before consuming the body
    let resp_ver = format_http_version(resp.version());
    let resp_body_bytes = match resp.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
            let body = Full::new(Bytes::from(format!(
                "upstream body collect error: {}",
                boxed
            )))
            .boxed();
            let resp = Response::builder()
                .status(500)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            let duration = started.elapsed().as_millis() as u64;
            let _ = build_and_write_transaction(
                captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                req_version.clone(),
                500,
                None,
                duration,
            )
            .await;
            return Ok(resp);
        }
    };

    let duration = started.elapsed().as_millis() as u64;

    let mut tx = crate::http_transaction::HttpTransaction::new(
        client_id.clone(),
        method.as_str().to_string(),
        uri_str.clone(),
    );
    tx.request.headers = req_headers.clone();
    tx.request.version = req_version.clone();
    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: headers.clone(),
        body_length: Some(resp_body_bytes.len() as u64),
    });
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };

    let violations = lint::lint_transaction(&tx, &shared.cfg, &shared.state, &shared.engine);
    tx.violations = violations.clone();

    shared.state.record_transaction(&tx);
    let _ = captures.write_transaction(&tx).await;

    let mut resp_builder = Response::builder().status(status);

    let connection_hop_headers = parse_connection_tokens(headers.get(hyper::header::CONNECTION));
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
            continue;
        }
        resp_builder = resp_builder.header(name, value);
    }
    let resp = resp_builder
        .body(Full::new(resp_body_bytes.clone()).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(resp_body_bytes.clone()).boxed()));

    Ok(resp)
}

// Parse a Connection header value into a lowercased set of tokens
fn parse_connection_tokens(
    val: Option<&hyper::header::HeaderValue>,
) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Some(conn_val) = val {
        if let Ok(conn_str) = conn_val.to_str() {
            for token in conn_str.split(',') {
                let trimmed = token.trim().to_ascii_lowercase();
                if !trimmed.is_empty() {
                    set.insert(trimmed);
                }
            }
        }
    }
    set
}

fn is_hop_by_hop_header(
    name: &str,
    connection_hop_headers: &std::collections::HashSet<String>,
) -> bool {
    connection_hop_headers.contains(name) || HOP_BY_HOP_HEADERS.contains(&name)
}

async fn handle_connect(
    client_conn: Upgraded,
    uri: Uri,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
) -> anyhow::Result<()> {
    let host = uri.host().unwrap_or("unknown");

    // Check for passthrough domains
    if shared
        .cfg
        .tls
        .passthrough_domains
        .iter()
        .any(|d| host.ends_with(d))
    {
        info!(%host, "tunneling connection (passthrough)");
        if let Err(e) = tunnel(client_conn, host, uri.port_u16().unwrap_or(443)).await {
            error!("tunnel error: {}", e);
        }
        return Ok(());
    }

    let ca = match shared.ca.as_ref() {
        Some(c) => c,
        None => {
            error!("handle_connect called when TLS CA is not configured");
            return Ok(());
        }
    };
    let cert = ca.gen_cert_for_domain(host)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolves(cert)));

    // Configure ALPN to support HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    // Wrap the hyper `Upgraded` (which implements hyper's `Read`/`Write`) with
    // `TokioIo` so it implements tokio's `AsyncRead`/`AsyncWrite` required by
    // `tokio_rustls::TlsAcceptor::accept`.
    let stream = acceptor.accept(TokioIo::new(client_conn)).await?;

    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        let conn_metadata = conn_metadata.clone();
        let fut: ServiceFuture = Box::pin(async move {
            handle_inner_request(req, shared, conn_metadata, hyper::http::uri::Scheme::HTTPS).await
        });
        fut
    });

    // Build an auto-detect HTTP connection for the TLS stream.
    let executor = TokioExecutor::new();
    let builder = hyper_util::server::conn::auto::Builder::new(executor);
    if let Err(e) = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
    {
        error!("TLS connection error: {}", e);
    }

    Ok(())
}

async fn tunnel(upgraded: Upgraded, host: &str, port: u16) -> std::io::Result<()> {
    trace!("tunnel: connecting to {}:{}", host, port);
    let mut server = tokio::net::TcpStream::connect((host, port)).await?;
    trace!("tunnel: connected to {}:{}", host, port);
    // Wrap both sides in TokioIo so they implement tokio::AsyncRead/Write
    let mut upgraded_io = TokioIo::new(upgraded);
    let (n1, n2) = tokio::io::copy_bidirectional(&mut upgraded_io, &mut server).await?;
    trace!("tunnel: copy finished: {} bytes -> {} bytes", n1, n2);
    Ok(())
}

#[cfg(test)]
async fn tunnel_with_io<S>(mut upgraded_io: S, host: &str, port: u16) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    trace!("tunnel (test helper): connecting to {}:{}", host, port);
    let mut server = tokio::net::TcpStream::connect((host, port)).await?;
    // Perform bidirectional copy between the upgraded side and the remote server
    let (n1, n2) = tokio::io::copy_bidirectional(&mut upgraded_io, &mut server).await?;
    trace!("tunnel: copy finished: {} bytes -> {} bytes", n1, n2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Request;
    use hyper_util::rt::TokioExecutor;
    use std::sync::Arc as StdArc;
    use tokio::fs;
    use uuid::Uuid;
    use wiremock::MockServer;
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handle_request_forwards_and_captures() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        use crate::test_helpers::make_test_config_with_enabled_rules;
        let cfg_inner = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let engine = crate::test_helpers::make_test_engine(&cfg_inner);
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(cfg_inner), None, Some(StdArc::new(engine))).await?;

        let req = make_request_with_headers("GET", mock.uri(), None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = read_capture(&tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        // Ensure that violations were captured (non-empty)
        assert!(v["violations"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_upstream_error() -> anyhow::Result<()> {
        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        // Use a port that is (likely) closed to provoke a client error
        let req = make_request_with_headers("GET", "http://127.0.0.1:9/", None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 502);

        let s = fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(502));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_with_relative_uri_builds_from_host() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rel"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        // Build a relative URI and set Host header so proxy builds absolute URI from Host
        let host = mock.address().to_string();
        let headers = [("host", host.as_str())];
        let req = make_request_with_headers("GET", "/rel", Some(&headers))?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let s = fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(200));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_no_violations_does_not_set_header() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes("ok".as_bytes())
                    .insert_header("cache-control", "max-age=1")
                    .insert_header("etag", "W/\"1\"")
                    .insert_header("x-content-type-options", "nosniff")
                    .insert_header("content-type", "text/plain; charset=utf-8"),
            )
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let uri = format!("{}/ok", mock.uri());
        let req = make_request_with_headers(
            "GET",
            uri,
            Some(&[("user-agent", "test-agent"), ("accept-encoding", "gzip")]),
        )?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let s = fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        // Ensure that there are no violations recorded
        assert!(v["violations"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_bind_fails_when_port_taken() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        // run_proxy should return an error since the port is already in use
        let res = run_proxy(addr, cw, shared.cfg.clone(), shared.engine.clone()).await;
        assert!(res.is_err());

        let _ = fs::remove_file(&tmp).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_capture_seed_load_error_logs_and_returns_error() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port so run_proxy will fail after startup
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        // Create a path that is a directory so load_captures will error when attempting to open it
        let dir = std::env::temp_dir().join(format!("lint_proxy_seed_dir_{}", Uuid::new_v4()));
        tokio::fs::create_dir(&dir).await?;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.general.captures_seed = true;
        cfg_inner.general.captures = dir.to_string_lossy().to_string();
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None, None).await?;

        // run_proxy should still return an error due to port being taken, but during
        // startup it should attempt to seed captures and hit the Err branch.
        let res = run_proxy(addr, cw, shared.cfg.clone(), shared.engine.clone()).await;
        assert!(res.is_err());

        // Cleanup
        let _ = fs::remove_file(&tmp).await;
        tokio::fs::remove_dir(&dir).await?;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_starts_and_can_be_aborted() -> anyhow::Result<()> {
        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, cw, shared.cfg.clone(), shared.engine.clone()).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        task.abort();
        let _ = task.await;

        tokio::fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_one_connection_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // pick a free port by binding to :0 then dropping the listener
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        // spawn the proxy with accept_limit = 1
        let cw_clone = cw.clone();
        let cfg_clone = shared.cfg.clone();
        let engine_clone = shared.engine.clone();
        let task = tokio::spawn(async move {
            run_proxy_with_limit(addr, cw_clone, cfg_clone, engine_clone, Some(1)).await
        });

        // Wait until we can connect (server startup may be slightly delayed)
        // Keep the stream open until the server task completes to avoid races where
        // the connection is reset before the server has a chance to accept it.
        let mut connected = false;
        let mut stream_opt: Option<TcpStream> = None;
        for _ in 0..20 {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    connected = true;
                    stream_opt = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        assert!(connected, "failed to connect to proxy");

        // task should finish shortly after the single accept
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), task).await??;
        assert!(res.is_ok());
        // Drop the stream now that the proxy has accepted it
        drop(stream_opt);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_zero_and_returns_immediately() -> anyhow::Result<()> {
        // pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (_shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        // accept_limit = 0 should return quickly
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_proxy_with_limit(
                addr,
                cw,
                _shared.cfg.clone(),
                _shared.engine.clone(),
                Some(0),
            ),
        )
        .await
        .expect("run_proxy_with_limit did not return within timeout")?;

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_two_connections_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        let task = tokio::spawn(async move {
            run_proxy_with_limit(addr, cw, shared.cfg.clone(), shared.engine.clone(), Some(2)).await
        });

        // make two connections and keep them open until the server finishes
        let mut streams: Vec<TcpStream> = Vec::new();
        for _ in 0..2 {
            let mut connected = false;
            for _ in 0..20 {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        connected = true;
                        streams.push(s);
                        break;
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
            }
            assert!(connected, "failed to connect to proxy");
        }

        // task should finish after two accepts
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), task).await??;
        assert!(res.is_ok());
        // Drop the streams now that the proxy has accepted them
        drop(streams);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_serves_ca_cert() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        let cfg = StdArc::new(cfg);

        // Create a temporary CA for the test
        let ca_dir = std::env::temp_dir().join(format!("lint_http_test_ca_{}", Uuid::new_v4()));
        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        let (shared, tmp, _cw) = make_shared_with_cfg(cfg.clone(), Some(ca.clone()), None).await?;

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/x-x509-ca-cert")
        );

        let body_bytes = resp.into_body().collect().await?;
        let body_str = String::from_utf8(body_bytes.to_bytes().to_vec())?;
        assert!(body_str.contains("BEGIN CERTIFICATE"));

        fs::remove_file(&tmp).await?;
        fs::remove_dir_all(&ca_dir).await?;
        Ok(())
    }

    use rstest::rstest;

    // Helper to create a Shared with a temp capture file for tests
    async fn make_shared_with_cfg(
        cfg: StdArc<crate::config::Config>,
        ca: Option<std::sync::Arc<CertificateAuthority>>,
        engine: Option<StdArc<crate::rules::RuleConfigEngine>>,
    ) -> anyhow::Result<(StdArc<Shared>, String, CaptureWriter)> {
        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_connect_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();
        let cw = CaptureWriter::new(p.clone()).await?;

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: LegacyClient<_, http_body_util::Full<bytes::Bytes>> =
            LegacyClient::builder(TokioExecutor::new()).build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));
        let engine = engine.unwrap_or_else(|| StdArc::new(crate::rules::RuleConfigEngine::new()));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca,
            engine,
        });
        Ok((shared, p, cw))
    }

    // Test helpers to reduce duplication
    fn boxed_empty() -> http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>
    {
        Full::new(Bytes::new()).boxed()
    }

    fn make_request_with_headers(
        method: &str,
        uri: impl AsRef<str>,
        headers: Option<&[(&str, &str)]>,
    ) -> anyhow::Result<
        hyper::Request<
            http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>,
        >,
    > {
        let mut builder = Request::builder().method(method).uri(uri.as_ref());
        if let Some(hs) = headers {
            for (k, v) in hs {
                builder = builder.header(*k, *v);
            }
        }
        Ok(builder.body(boxed_empty()).unwrap())
    }

    async fn read_capture(path: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let s = tokio::fs::read_to_string(path).await?;
        let mut entries = Vec::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(line)?);
        }
        Ok(entries)
    }

    #[tokio::test]
    #[rstest]
    #[case(false, false, 405u16)]
    #[case(false, true, 200u16)]
    #[case(true, false, 405u16)]
    #[case(true, true, 405u16)]
    async fn connect_cases(
        #[case] use_inner: bool,
        #[case] ca_present: bool,
        #[case] expected_status: u16,
    ) -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        if ca_present {
            cfg.tls.enabled = true;
        }
        let cfg = StdArc::new(cfg);

        let ca_arc = if ca_present {
            let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", Uuid::new_v4()));
            let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", Uuid::new_v4()));
            let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;
            Some(ca)
        } else {
            None
        };

        let (shared, tmp_path, _cw) = make_shared_with_cfg(cfg, ca_arc.clone(), None).await?;

        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));

        let resp = if use_inner {
            handle_inner_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?
        } else {
            handle_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?
        };

        assert_eq!(resp.status().as_u16(), expected_status);

        let _ = fs::remove_file(&tmp_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_connect_without_tls_returns_405() -> anyhow::Result<()> {
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        // Try to use CONNECT method
        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Should return 405 because TLS is disabled
        assert_eq!(resp.status().as_u16(), 405);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    // Replaced by parameterized `connect_cases` test to reduce duplication.

    #[tokio::test]
    async fn handle_request_filters_hop_by_hop_headers() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/hop"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("connection", "keep-alive, foo")
                    .insert_header("foo", "bar"),
            )
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let req = make_request_with_headers("GET", format!("{}/hop", mock.uri()), None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // 'connection' and 'foo' should be filtered out
        assert!(resp.headers().get("connection").is_none());
        assert!(resp.headers().get("foo").is_none());

        // Also verify that parse_connection_tokens handles various token formats
        use hyper::header::HeaderValue;
        let parsed =
            super::parse_connection_tokens(Some(&HeaderValue::from_static("keep-alive, Foo ,")));
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("foo"));
        assert!(
            super::parse_connection_tokens(Some(&HeaderValue::from_static(" , ,a,b")))
                .contains("a")
        );

        // Now ensure a static hop-by-hop header like 'transfer-encoding' is removed
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/hop2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("transfer-encoding", "chunked"),
            )
            .mount(&mock)
            .await;

        let uri2: Uri = format!("{}/hop2", mock.uri()).parse()?;
        let req2 = Request::builder()
            .method("GET")
            .uri(uri2)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata2 = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp2 = handle_request(
            req2,
            shared.clone(),
            conn_metadata2,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        assert!(resp2.headers().get("transfer-encoding").is_none());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[test]
    fn hop_by_hop_headers_are_recognized() {
        use std::collections::HashSet;
        // Empty set of connection tokens means we rely solely on the static list
        let set: HashSet<String> = HashSet::new();
        for &h in HOP_BY_HOP_HEADERS.iter() {
            assert!(is_hop_by_hop_header(h, &set));
        }
        // A non-standard header should not be recognized
        assert!(!is_hop_by_hop_header("x-not-hop", &set));

        // If the connection header explicitly names a token, it should be recognized
        let mut conn_set: HashSet<String> = HashSet::new();
        conn_set.insert("x-not-hop".to_string());
        assert!(is_hop_by_hop_header("x-not-hop", &conn_set));
    }

    #[test]
    fn hop_by_hop_header_constants_have_expected_entries() {
        // Ensure the static list contains known hop-by-hop headers
        assert!(HOP_BY_HOP_HEADERS.contains(&"connection"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"upgrade"));
    }

    #[test]
    fn parse_connection_tokens_handles_non_utf8() {
        use hyper::header::HeaderValue;
        // Construct a header value that is not valid UTF-8
        let hv = HeaderValue::from_bytes(&[0xffu8]).expect("create header val");
        let parsed = super::parse_connection_tokens(Some(&hv));
        // to_str() will fail and we should just return empty set
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn handle_request_ca_cert_endpoint_without_tls_returns_404() -> anyhow::Result<()> {
        let cfg = StdArc::new(crate::config::Config::default()); // TLS disabled by default
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Should return 404 because TLS is not enabled
        assert_eq!(resp.status().as_u16(), 404);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    // Replaced by parameterized `connect_cases` test to reduce duplication.

    // A custom Body that returns an error on collection to trigger the body collect error path
    struct FailingBody;

    impl hyper::body::Body for FailingBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            // Simulate an immediate body collection error
            std::task::Poll::Ready(Some(Err(std::io::Error::other("simulated body error"))))
        }
    }

    #[tokio::test]
    async fn handle_http_logic_body_collect_error_returns_500() -> anyhow::Result<()> {
        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/error")
            .body(FailingBody)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        assert_eq!(resp.status().as_u16(), 500);
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_respects_suppress_headers() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.tls.suppress_headers = vec!["user-agent".to_string()];
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let uri: Uri = mock.uri().parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("user-agent", "should-be-suppressed")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        // Ensure the upstream mock did not receive the suppressed header
        let requests = mock
            .received_requests()
            .await
            .expect("expected one request to be received");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("user-agent").is_none());

        let entries = read_capture(&tmp).await?;
        let v = &entries[0];
        // The capture still records the original request headers (suppression only affects upstream)
        assert!(v["request"]["headers"].get("user-agent").is_some());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_various_upstream_responses_exercises_rules() -> anyhow::Result<()> {
        use crate::test_helpers::make_test_config_with_enabled_rules;

        let mock = MockServer::start().await;

        // 1) 200 with no content-type -> should trigger server_content_type_present
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/no-content-type"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        // 2) 200 with no etag/last-modified -> should trigger server_etag_or_last_modified
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/no-etag"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        // 3) 405 with no Allow -> should trigger server_response_405_allow
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/405-no-allow"))
            .respond_with(ResponseTemplate::new(405).set_body_string("not allowed"))
            .mount(&mock)
            .await;

        let cfg_inner = make_test_config_with_enabled_rules(&[
            "server_content_type_present",
            "server_etag_or_last_modified",
            "server_response_405_allow",
        ]);
        let engine = crate::test_helpers::make_test_engine(&cfg_inner);
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(cfg_inner), None, Some(StdArc::new(engine))).await?;

        let cases = vec!["/no-content-type", "/no-etag", "/405-no-allow"];
        for path in cases {
            let uri: Uri = format!("{}{}", mock.uri(), path).parse()?;
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .body(Full::new(Bytes::new()).boxed())?;

            let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
                "127.0.0.1:12345".parse()?,
            ));
            let resp = handle_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?;

            assert!(resp.status().as_u16() == 200 || resp.status().as_u16() == 405);
        }

        // Read the capture file and ensure there is at least one violation recorded among the JSONL entries
        let s = tokio::fs::read_to_string(&tmp).await?;
        let mut found_violation = false;
        for line in s.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(line)?;
            if v["violations"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                found_violation = true;
                break;
            }
        }
        assert!(
            found_violation,
            "expected at least one capture with a violation"
        );

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_capture_seed_load_success() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port so run_proxy will fail after startup
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        // Create a temporary captures JSONL with a single valid transaction
        let tmp_capture =
            std::env::temp_dir().join(format!("lint_proxy_seed_ok_{}.jsonl", Uuid::new_v4()));
        let pcap = tmp_capture
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Write a minimal transaction record
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.uri = "http://example/seed".to_string();
        let line = serde_json::to_string(&tx)? + "\n";
        tokio::fs::write(&tmp_capture, line).await?;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.general.captures_seed = true;
        cfg_inner.general.captures = pcap.clone();
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None, None).await?;

        // run_proxy should attempt to load captures and then fail on bind
        let res = run_proxy(addr, cw, shared.cfg.clone(), shared.engine.clone()).await;
        assert!(res.is_err());

        // Cleanup
        let _ = fs::remove_file(&tmp).await;
        let _ = tokio::fs::remove_file(&tmp_capture).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_tls_enabled_starts_and_can_be_aborted() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        // Use temp paths for CA files
        let cert_path = std::env::temp_dir().join(format!("test_ca_run_{}.crt", Uuid::new_v4()));
        let key_path = std::env::temp_dir().join(format!("test_ca_run_{}.key", Uuid::new_v4()));
        cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
        cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

        let cfg = StdArc::new(cfg);
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg.clone(), None, None).await?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, _cw, shared.cfg.clone(), shared.engine.clone()).await;
        });

        // Wait up to 2s for the CA files to be created by startup
        let start = std::time::Instant::now();
        while !(cert_path.exists() && key_path.exists()) {
            if start.elapsed() > std::time::Duration::from_secs(2) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        task.abort();
        let _ = task.await;

        // Ensure CA files were created by startup
        assert!(cert_path.exists());
        assert!(key_path.exists());

        tokio::fs::remove_file(&cert_path).await?;
        tokio::fs::remove_file(&key_path).await?;
        tokio::fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_relative_uri_with_invalid_host_falls_back_and_returns_502(
    ) -> anyhow::Result<()> {
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None, None).await?;

        // Relative URI with invalid Host header should fail to parse and fallback to localhost
        let req = Request::builder()
            .method("GET")
            .uri("/willfail")
            .header(hyper::header::HOST, "bad host")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Expect 502 (or 400 in case of immediate request rejection) because client will fail to connect to localhost
        let status = resp.status().as_u16();
        assert!(
            status == 502 || status == 400,
            "unexpected status: {}",
            status
        );

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_upstream_body_collect_error_returns_500() -> anyhow::Result<()> {
        // Start a raw TCP server that returns a truncated response body
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                // Read the request (drain input)
                let mut buf = [0u8; 1024];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);

                // Write headers with Content-Length 10 but only send 3 bytes, then close
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
                let _ = socket.try_write(resp);
                // Drop socket to close connection prematurely
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/", addr.port()).parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        assert_eq!(resp.status().as_u16(), 500);

        let _ = server_task.await;
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_copies_data_between_sides() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a simple TCP server that reads 'ping' and replies 'pong'
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4];
                if sock.read_exact(&mut buf).await.is_ok() {
                    assert_eq!(&buf, b"ping");
                    let _ = sock.write_all(b"pong").await;
                }
            }
        });

        // Create a duplex pair to simulate the upgraded client side
        let (mut client_side, server_side) = tokio::io::duplex(64);

        // Run the tunnel helper which will connect to the mock server and copy data
        let t = tokio::spawn(
            async move { super::tunnel_with_io(server_side, "127.0.0.1", port).await },
        );

        // Write 'ping' from the client side and read 'pong' in response
        tokio::io::AsyncWriteExt::write_all(&mut client_side, b"ping").await?;
        let mut resp = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut resp).await?;
        assert_eq!(&resp, b"pong");

        // Close the client side to let tunnel finish
        drop(client_side);
        let res = t.await?;
        assert!(res.is_ok());

        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_fails_when_remote_not_listening() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        // pick a currently-unused port by binding and dropping
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        // Create a duplex pair to simulate the upgraded client side
        let (mut client_side, server_side) = tokio::io::duplex(64);

        // Run the tunnel helper which should fail to connect
        let t = tokio::spawn(
            async move { super::tunnel_with_io(server_side, "127.0.0.1", port).await },
        );

        // Write some data; the tunnel should error when trying to connect
        let _ = client_side.write_all(b"ping").await;

        let res = t.await?;
        assert!(res.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_completes_when_remote_closes_early() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        // Start a simple TCP server that reads a couple bytes then closes
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // read two bytes then close
                let mut buf = [0u8; 2];
                let _ = sock.read_exact(&mut buf).await;
                // drop socket to close prematurely
                drop(sock);
            }
        });

        let (mut client_side, server_side) = tokio::io::duplex(64);
        let t = tokio::spawn(
            async move { super::tunnel_with_io(server_side, "127.0.0.1", port).await },
        );

        // send 4 bytes even though server only reads 2 and then closes
        client_side.write_all(b"ping").await?;

        // closing client side to let tunnel finish
        drop(client_side);
        // Ensure the tunnel finishes quickly instead of hanging indefinitely.
        let res = timeout(std::time::Duration::from_secs(2), t)
            .await
            .map_err(|_| anyhow::anyhow!("tunnel did not complete within timeout"))??;
        // The tunnel may succeed or return an IO error depending on timing; that's acceptable
        // as long as it didn't hang or panic (timeout/JoinError would have been returned above).
        let _ = res;
        let _ = server_task.await;
        Ok(())
    }
}
