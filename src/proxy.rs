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
use tracing::{error, info, trace, warn};

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
        hyper::Version::HTTP_3 => "HTTP/3".to_string(),
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
    #[case(Version::HTTP_3, "HTTP/3")]
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
    protocol_event_store: Arc<crate::protocol_event_store::ProtocolEventStore>,
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
    let max_history = cfg.general.max_history;
    let state = Arc::new(crate::state::StateStore::new(ttl, max_history));
    let protocol_event_store = Arc::new(crate::protocol_event_store::ProtocolEventStore::new(
        ttl,
        cfg.general.max_protocol_event_history,
    ));

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
    let pe_store_cleanup = protocol_event_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            state_cleanup.cleanup_expired();
            pe_store_cleanup.cleanup_expired();
        }
    });

    let shared = Arc::new(Shared {
        client,
        captures,
        cfg,
        state,
        protocol_event_store,
        ca,
        engine,
    });

    // Start HTTP/3 (QUIC) listener if configured.
    // Initialization (cert generation, QUIC bind) is done synchronously so that
    // misconfigurations surface immediately rather than silently failing in a
    // background task.
    if let Some(ref h3_listen) = shared.cfg.general.h3_listen {
        let h3_addr: SocketAddr = h3_listen.parse()?;
        let ca = shared
            .ca
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("h3_listen requires TLS to be enabled"))?
            .clone();
        let server_name = shared
            .cfg
            .general
            .h3_server_name
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let endpoint = init_h3_endpoint(h3_addr, &server_name, &ca)?;
        let shared_h3 = shared.clone();
        tokio::spawn(async move {
            run_h3_accept_loop(endpoint, shared_h3).await;
        });
    }

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
    mut req: Request<B>,
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
        req_body: Option<bytes::Bytes>,
    ) -> anyhow::Result<()> {
        let mut tx = crate::http_transaction::HttpTransaction::new(
            client_id.clone(),
            method.to_string(),
            uri_str.to_string(),
        );
        tx.request.headers = req_headers.clone();
        tx.request.version = req_version;
        if let Some(b) = req_body {
            tx.request.body_length = Some(b.len() as u64);
            tx.request_body = Some(b);
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: response_headers.unwrap_or_default(),
            body_length: None,
            trailers: None,
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

    let is_ws_upgrade = is_websocket_upgrade(&req);

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

    // Extract the client OnUpgrade before consuming the request body.
    // For WebSocket upgrades, we need this to get the upgraded client IO later.
    let client_on_upgrade = if is_ws_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let body = req.into_body();
    let captures = &shared.captures;

    let (body_bytes, req_trailers) = match body.collect().await {
        Ok(collected) => {
            let trailers = collected.trailers().cloned();
            (collected.to_bytes(), trailers)
        }
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
                None,
            )
            .await;
            return Ok(resp);
        }
    };

    let upstream_req = match builder.body(Full::new(body_bytes.clone())) {
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
                Some(body_bytes.clone()),
            )
            .await;
            return Ok(resp);
        }
    };

    // WebSocket upgrade path: bypass LegacyClient, use direct connection with
    // upgrade support, and spawn a relay task for frame-level capture.
    if is_ws_upgrade {
        if let Some(client_on_upgrade) = client_on_upgrade {
            return handle_websocket_upgrade(
                upstream_req,
                client_on_upgrade,
                &uri,
                &scheme,
                &started,
                &client_id,
                &method,
                &uri_str,
                &req_headers,
                &req_version,
                body_bytes,
                req_trailers,
                shared,
                conn_metadata,
            )
            .await;
        }
    }

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
                Some(body_bytes.clone()),
            )
            .await;
            return Ok(resp);
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    // Capture the upstream response version before consuming the body
    let resp_ver = format_http_version(resp.version());
    let (resp_body_bytes, resp_trailers) = match resp.into_body().collect().await {
        Ok(collected) => {
            let trailers = collected.trailers().cloned();
            (collected.to_bytes(), trailers)
        }
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
                Some(body_bytes.clone()),
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
    // record request body and length
    tx.request.body_length = Some(body_bytes.len() as u64);
    tx.request.trailers = req_trailers;
    tx.request_body = Some(body_bytes.clone());

    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: headers.clone(),
        body_length: Some(resp_body_bytes.len() as u64),
        trailers: resp_trailers,
    });
    tx.response_body = Some(resp_body_bytes.clone());
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };
    tx.connection_id = Some(conn_metadata.id);
    tx.sequence_number = Some(conn_metadata.next_sequence_number());
    if status == 101 {
        tx.was_upgraded = true;
        tx.upgrade_protocol = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
    }

    let violations = lint::lint_transaction(&tx, &shared.cfg, &shared.state, &shared.engine);
    tx.violations = violations.clone();

    shared.state.record_transaction(&tx);
    let _ = captures.write_transaction(&tx).await;

    let mut resp_builder = Response::builder().status(status);

    if status == 101 {
        // 101 Switching Protocols: preserve all headers including Connection
        // and Upgrade which are essential for the upgrade handshake.
        for (name, value) in headers.iter() {
            resp_builder = resp_builder.header(name, value);
        }
    } else {
        let connection_hop_headers =
            parse_connection_tokens(headers.get(hyper::header::CONNECTION));
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_ascii_lowercase();
            if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
                continue;
            }
            resp_builder = resp_builder.header(name, value);
        }
    }
    let resp = resp_builder
        .body(Full::new(resp_body_bytes.clone()).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(resp_body_bytes.clone()).boxed()));

    Ok(resp)
}

/// Handle a WebSocket upgrade request: connect directly to upstream, relay
/// frames via tokio-tungstenite, and capture the session.
#[allow(clippy::too_many_arguments)]
async fn handle_websocket_upgrade(
    upstream_req: Request<Full<Bytes>>,
    client_on_upgrade: hyper::upgrade::OnUpgrade,
    uri: &Uri,
    scheme: &hyper::http::uri::Scheme,
    started: &Instant,
    client_id: &crate::state::ClientIdentifier,
    method: &Method,
    uri_str: &str,
    req_headers: &hyper::HeaderMap,
    req_version: &str,
    body_bytes: Bytes,
    req_trailers: Option<hyper::HeaderMap>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let captures = &shared.captures;

    // Connect directly to upstream with upgrade support
    let (mut sender, _conn_handle) = match connect_upstream_for_upgrade(uri, scheme).await {
        Ok(s) => s,
        Err(e) => {
            error!("websocket upstream connect error: {}", e);
            let body = Full::new(Bytes::from(format!("websocket upstream error: {}", e))).boxed();
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            return Ok(resp);
        }
    };

    // Send the upgrade request to the upstream server
    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("websocket upstream request error: {}", e);
            let body = Full::new(Bytes::from(format!("websocket upstream error: {}", e))).boxed();
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("upstream error")).boxed())
                });
            return Ok(resp);
        }
    };

    let status = upstream_resp.status().as_u16();
    let headers = upstream_resp.headers().clone();
    let resp_ver = format_http_version(upstream_resp.version());
    let duration = started.elapsed().as_millis() as u64;

    // Record the HTTP transaction (the 101 handshake)
    let mut tx = crate::http_transaction::HttpTransaction::new(
        client_id.clone(),
        method.as_str().to_string(),
        uri_str.to_string(),
    );
    tx.request.headers = req_headers.clone();
    tx.request.version = req_version.to_string();
    tx.request.body_length = Some(body_bytes.len() as u64);
    tx.request.trailers = req_trailers;
    tx.request_body = Some(body_bytes);
    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: headers.clone(),
        body_length: Some(0),
        trailers: None,
    });
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };
    tx.connection_id = Some(conn_metadata.id);
    tx.sequence_number = Some(conn_metadata.next_sequence_number());
    if status == 101 {
        tx.was_upgraded = true;
        tx.upgrade_protocol = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
    }

    let violations = lint::lint_transaction(&tx, &shared.cfg, &shared.state, &shared.engine);
    tx.violations = violations.clone();
    shared.state.record_transaction(&tx);
    let _ = captures.write_transaction(&tx).await;

    let tx_id = tx.id;

    if status == 101 {
        // Extract the server-side upgraded IO
        let server_upgraded = hyper::upgrade::on(&mut upstream_resp);

        // Build the 101 response to send back to the client.
        // Forward ALL headers including upgrade-related ones (Connection, Upgrade,
        // Sec-WebSocket-Accept) — do NOT strip hop-by-hop headers for 101.
        let mut resp_builder = Response::builder().status(101);
        for (name, value) in headers.iter() {
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(Full::new(Bytes::new()).boxed())
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()));

        // Spawn background relay task
        let captures_clone = shared.captures.clone();
        let pe_ctx = ProtocolLintCtx {
            connection_id: conn_metadata.id,
            store: shared.protocol_event_store.clone(),
            cfg: shared.cfg.clone(),
            engine: shared.engine.clone(),
        };
        tokio::spawn(async move {
            // Wait for both sides to complete the upgrade
            let (client_io, server_io) = match tokio::try_join!(client_on_upgrade, server_upgraded)
            {
                Ok((c, s)) => (c, s),
                Err(e) => {
                    error!("websocket upgrade failed: {}", e);
                    return;
                }
            };

            relay_websocket(
                TokioIo::new(client_io),
                TokioIo::new(server_io),
                tx_id,
                captures_clone,
                pe_ctx,
            )
            .await;
        });

        Ok(resp)
    } else {
        // Upstream did not accept the upgrade; return the response normally
        let resp_body = match upstream_resp.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => Bytes::new(),
        };

        let mut resp_builder = Response::builder().status(status);
        let connection_hop_headers =
            parse_connection_tokens(headers.get(hyper::header::CONNECTION));
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_ascii_lowercase();
            if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
                continue;
            }
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(Full::new(resp_body).boxed())
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()));

        Ok(resp)
    }
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

/// Check if a request is a WebSocket upgrade request.
fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let has_upgrade = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    let is_websocket = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    has_upgrade && is_websocket
}

/// Open a direct TCP (or TLS) connection to the upstream host and perform
/// an HTTP/1.1 handshake with upgrade support.
async fn connect_upstream_for_upgrade(
    uri: &Uri,
    scheme: &hyper::http::uri::Scheme,
) -> anyhow::Result<(
    hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
)> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in URI"))?;
    let port = uri
        .port_u16()
        .unwrap_or(if *scheme == hyper::http::uri::Scheme::HTTPS {
            443
        } else {
            80
        });

    let tcp = tokio::net::TcpStream::connect((host, port)).await?;

    if *scheme == hyper::http::uri::Scheme::HTTPS {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            root_store.add(cert).ok();
        }
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(server_name, tcp).await?;

        let (sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
        let handle = tokio::spawn(conn.with_upgrades());
        Ok((sender, handle))
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        let handle = tokio::spawn(conn.with_upgrades());
        Ok((sender, handle))
    }
}

/// Context for protocol-event linting during WebSocket relay.
struct ProtocolLintCtx {
    connection_id: uuid::Uuid,
    store: Arc<crate::protocol_event_store::ProtocolEventStore>,
    cfg: Arc<Config>,
    engine: Arc<crate::rules::RuleConfigEngine>,
}

/// Relay WebSocket messages between client and server, recording each message
/// for capture. Uses tokio-tungstenite for proper RFC 6455 frame parsing.
async fn relay_websocket(
    client_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    server_io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    tx_id: uuid::Uuid,
    captures: CaptureWriter,
    pe_ctx: ProtocolLintCtx,
) {
    use crate::websocket_session::{MessageDirection, WebSocketMessageInfo, WebSocketSession};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    let client_ws =
        tokio_tungstenite::WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
    let server_ws =
        tokio_tungstenite::WebSocketStream::from_raw_socket(server_io, Role::Client, None).await;

    let (mut client_write, mut client_read) = client_ws.split();
    let (mut server_write, mut server_read) = server_ws.split();

    let session_id = uuid::Uuid::new_v4();
    let messages = Arc::new(tokio::sync::Mutex::new(Vec::<WebSocketMessageInfo>::new()));
    let violations = Arc::new(tokio::sync::Mutex::new(Vec::<crate::lint::Violation>::new()));
    let close_code = Arc::new(tokio::sync::Mutex::new(None::<u16>));
    let start = Instant::now();

    let pe_store = pe_ctx.store;
    let pe_cfg = pe_ctx.cfg;
    let pe_engine = pe_ctx.engine;
    let connection_id = pe_ctx.connection_id;

    let msgs_c2s = messages.clone();
    let viols_c2s = violations.clone();
    let close_c2s = close_code.clone();
    let pe_store_c2s = pe_store.clone();
    let cfg_c2s = pe_cfg.clone();
    let engine_c2s = pe_engine.clone();
    let c2s = async move {
        while let Some(result) = client_read.next().await {
            match result {
                Ok(msg) => {
                    let info = message_to_info(&msg, MessageDirection::Client);
                    if let tokio_tungstenite::tungstenite::Message::Close(Some(ref frame)) = msg {
                        let mut cc = close_c2s.lock().await;
                        if cc.is_none() {
                            *cc = Some(frame.code.into());
                        }
                    }
                    // Emit protocol event and lint it
                    let pe = crate::protocol_event::ProtocolEvent {
                        timestamp: chrono::Utc::now(),
                        connection_id,
                        kind: crate::protocol_event::ProtocolEventKind::WebSocketFrame {
                            session_id,
                            direction: info.direction,
                            fin: info.fin,
                            opcode: info.opcode,
                            rsv: info.rsv,
                            payload_length: info.payload_length,
                        },
                    };
                    let v = crate::lint_protocol::lint_protocol_event(
                        &pe,
                        &cfg_c2s,
                        &pe_store_c2s,
                        &engine_c2s,
                    );
                    pe_store_c2s.record_event(&pe);
                    if !v.is_empty() {
                        viols_c2s.lock().await.extend(v);
                    }

                    msgs_c2s.lock().await.push(info);
                    if server_write.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let msgs_s2c = messages.clone();
    let viols_s2c = violations.clone();
    let close_s2c = close_code.clone();
    let pe_store_s2c = pe_store.clone();
    let cfg_s2c = pe_cfg.clone();
    let engine_s2c = pe_engine.clone();
    let s2c = async move {
        while let Some(result) = server_read.next().await {
            match result {
                Ok(msg) => {
                    let info = message_to_info(&msg, MessageDirection::Server);
                    if let tokio_tungstenite::tungstenite::Message::Close(Some(ref frame)) = msg {
                        let mut cc = close_s2c.lock().await;
                        if cc.is_none() {
                            *cc = Some(frame.code.into());
                        }
                    }
                    // Emit protocol event and lint it
                    let pe = crate::protocol_event::ProtocolEvent {
                        timestamp: chrono::Utc::now(),
                        connection_id,
                        kind: crate::protocol_event::ProtocolEventKind::WebSocketFrame {
                            session_id,
                            direction: info.direction,
                            fin: info.fin,
                            opcode: info.opcode,
                            rsv: info.rsv,
                            payload_length: info.payload_length,
                        },
                    };
                    let v = crate::lint_protocol::lint_protocol_event(
                        &pe,
                        &cfg_s2c,
                        &pe_store_s2c,
                        &engine_s2c,
                    );
                    pe_store_s2c.record_event(&pe);
                    if !v.is_empty() {
                        viols_s2c.lock().await.extend(v);
                    }

                    msgs_s2c.lock().await.push(info);
                    if client_write.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Run both directions concurrently; when either finishes, the session is done.
    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut session = WebSocketSession::new(tx_id);
    session.id = session_id;
    session.duration_ms = duration_ms;
    session.messages = match Arc::try_unwrap(messages) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().await.clone(),
    };
    session.close_code = match Arc::try_unwrap(close_code) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => *arc.lock().await,
    };
    session.violations = match Arc::try_unwrap(violations) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().await.clone(),
    };

    if let Err(e) = captures.write_websocket_session(&session).await {
        error!("failed to write websocket session: {}", e);
    }
}

fn message_to_info(
    msg: &tokio_tungstenite::tungstenite::Message,
    direction: crate::websocket_session::MessageDirection,
) -> crate::websocket_session::WebSocketMessageInfo {
    use crate::websocket_session::WebSocketMessageInfo;
    let (opcode, payload_length, fin, rsv) = match msg {
        // Assembled messages: tungstenite has already defragmented, so FIN is
        // implicitly true and RSV bits are not available.
        tokio_tungstenite::tungstenite::Message::Text(s) => (1, s.len() as u64, true, 0u8),
        tokio_tungstenite::tungstenite::Message::Binary(b) => (2, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Ping(b) => (9, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Pong(b) => (10, b.len() as u64, true, 0),
        tokio_tungstenite::tungstenite::Message::Close(frame) => {
            let len = frame
                .as_ref()
                .map(|f| 2 + f.reason.len() as u64)
                .unwrap_or(0);
            (8, len, true, 0)
        }
        // Raw Frame variant: extract actual FIN and RSV bits from header.
        tokio_tungstenite::tungstenite::Message::Frame(f) => {
            let hdr = f.header();
            let rsv_bits = ((hdr.rsv1 as u8) << 2) | ((hdr.rsv2 as u8) << 1) | (hdr.rsv3 as u8);
            (
                u8::from(hdr.opcode),
                f.payload().len() as u64,
                hdr.is_final,
                rsv_bits,
            )
        }
    };
    WebSocketMessageInfo {
        direction,
        opcode,
        payload_length,
        fin,
        rsv,
    }
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

// ---------------------------------------------------------------------------
// HTTP/3 (QUIC) listener
// ---------------------------------------------------------------------------

/// Create a QUIC endpoint bound to `addr` with a TLS certificate for
/// `server_name`.  This performs all fallible initialization (cert generation,
/// socket bind) synchronously so errors propagate to the caller.
fn init_h3_endpoint(
    addr: SocketAddr,
    server_name: &str,
    ca: &CertificateAuthority,
) -> anyhow::Result<quinn::Endpoint> {
    let cert = ca.gen_cert_for_domain(server_name)?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolves(cert)));
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("failed to build QUIC server config: {}", e))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    info!(%addr, "HTTP/3 (QUIC) listening");
    Ok(endpoint)
}

/// Accept loop for an already-bound QUIC endpoint.  Each incoming connection
/// is handled in a spawned task through the same pipeline as TCP traffic.
async fn run_h3_accept_loop(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let shared = shared.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote_addr = conn.remote_address();
                    if let Err(e) = handle_h3_connection(conn, shared, remote_addr).await {
                        error!("HTTP/3 connection error: {}", e);
                    }
                }
                Err(e) => {
                    error!("HTTP/3 incoming connection error: {}", e);
                }
            }
        });
    }
}

/// Handle a single HTTP/3 connection: accept request streams, forward upstream,
/// lint, capture, and return responses.
async fn handle_h3_connection(
    conn: quinn::Connection,
    shared: Arc<Shared>,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    let conn_metadata = Arc::new(crate::connection::ConnectionMetadata::new_quic(remote_addr));
    let connection_id = conn_metadata.id;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let stream_id = conn_metadata.next_sequence_number() as u64;

                // Emit H3StreamOpened protocol event
                emit_h3_protocol_event(
                    crate::protocol_event::ProtocolEventKind::H3StreamOpened { stream_id },
                    connection_id,
                    &shared,
                );

                let shared = shared.clone();
                let conn_metadata = conn_metadata.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(
                                req,
                                stream,
                                shared.clone(),
                                conn_metadata,
                                stream_id,
                            )
                            .await
                            {
                                error!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("HTTP/3 resolve request error: {}", e);
                        }
                    }
                    // Emit H3StreamClosed when the stream task completes
                    emit_h3_protocol_event(
                        crate::protocol_event::ProtocolEventKind::H3StreamClosed { stream_id },
                        connection_id,
                        &shared,
                    );
                });
            }
            Ok(None) => {
                // Connection closed gracefully.  The h3 crate does not
                // expose the GOAWAY stream ID, so we emit None.
                emit_h3_protocol_event(
                    crate::protocol_event::ProtocolEventKind::H3GoawayReceived { stream_id: None },
                    connection_id,
                    &shared,
                );
                break;
            }
            Err(e) => {
                error!("HTTP/3 accept error: {}", e);
                break;
            }
        }
    }
    Ok(())
}

/// Emit an HTTP/3 protocol event: lint it, record it, and log any violations.
fn emit_h3_protocol_event(
    kind: crate::protocol_event::ProtocolEventKind,
    connection_id: uuid::Uuid,
    shared: &Shared,
) {
    let pe = crate::protocol_event::ProtocolEvent {
        timestamp: chrono::Utc::now(),
        connection_id,
        kind,
    };
    let violations = crate::lint_protocol::lint_protocol_event(
        &pe,
        &shared.cfg,
        &shared.protocol_event_store,
        &shared.engine,
    );
    shared.protocol_event_store.record_event(&pe);
    for v in &violations {
        warn!(
            rule = %v.rule,
            severity = ?v.severity,
            "H3 protocol violation: {}",
            v.message
        );
    }
}

/// Process a single HTTP/3 request: collect body, forward upstream via the
/// shared hyper client, lint the transaction, write captures, and stream the
/// response back over h3.
///
/// HTTP/3 does not support 101 Switching Protocols (RFC 9114 §4.2), so
/// upgrade/WebSocket handling is intentionally omitted here.
async fn handle_h3_request(
    req: hyper::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    stream_id: u64,
) -> anyhow::Result<()> {
    use bytes::Buf;

    let started = Instant::now();

    // Collect the request body from the h3 stream
    let mut req_body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut buf = chunk;
        while buf.has_remaining() {
            let bytes = buf.chunk();
            req_body.extend_from_slice(bytes);
            let len = bytes.len();
            buf.advance(len);
        }
    }
    let req_body_bytes = Bytes::from(req_body);

    // Collect request trailers (if the client sent any after the body)
    let req_trailers = match stream.recv_trailers().await {
        Ok(t) => t,
        Err(e) => {
            trace!("HTTP/3 request trailers error (non-fatal): {}", e);
            None
        }
    };

    // Build the upstream URI
    let uri = {
        let scheme = req
            .uri()
            .scheme()
            .cloned()
            .unwrap_or(hyper::http::uri::Scheme::HTTPS);
        let host = req
            .uri()
            .authority()
            .map(|a: &hyper::http::uri::Authority| a.as_str())
            .or_else(|| {
                req.headers()
                    .get(hyper::header::HOST)
                    .and_then(|h: &hyper::header::HeaderValue| h.to_str().ok())
            })
            .unwrap_or("localhost");
        let path = req
            .uri()
            .path_and_query()
            .map(|pq: &hyper::http::uri::PathAndQuery| pq.as_str())
            .unwrap_or("/");
        format!("{}://{}{}", scheme, host, path)
            .parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("https://localhost/"))
    };

    let method = req.method().clone();
    let uri_str = req.uri().to_string();
    let req_headers = req.headers().clone();

    let client_ip = conn_metadata.remote_addr.ip();
    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let client_id = crate::state::ClientIdentifier::new(client_ip, user_agent);

    // Build upstream request (forwarded over TCP via the existing hyper client)
    let mut builder = Request::builder().method(method.clone()).uri(uri.clone());
    for (name, value) in req_headers.iter() {
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

    let upstream_req = builder.body(Full::new(req_body_bytes.clone()))?;

    /// Record a minimal error transaction on the H3 path (mirrors TCP path's
    /// `build_and_write_transaction`).
    #[allow(clippy::too_many_arguments)]
    async fn record_h3_error(
        captures: &CaptureWriter,
        client_id: &crate::state::ClientIdentifier,
        method: &str,
        uri_str: &str,
        req_headers: &hyper::HeaderMap,
        req_body: &Bytes,
        status: u16,
        duration_ms: u64,
        conn_metadata: &crate::connection::ConnectionMetadata,
        sequence_number: u32,
    ) {
        let mut tx = crate::http_transaction::HttpTransaction::new(
            client_id.clone(),
            method.to_string(),
            uri_str.to_string(),
        );
        tx.request.headers = req_headers.clone();
        tx.request.version = "HTTP/3".to_string();
        tx.request.body_length = Some(req_body.len() as u64);
        tx.request_body = Some(req_body.clone());
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/3".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });
        tx.timing = crate::http_transaction::TimingInfo { duration_ms };
        tx.connection_id = Some(conn_metadata.id);
        tx.sequence_number = Some(sequence_number);
        let _ = captures.write_transaction(&tx).await;
    }

    let resp = match shared.client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("HTTP/3 upstream error: {}", e);
            let duration = started.elapsed().as_millis() as u64;
            record_h3_error(
                &shared.captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                &req_body_bytes,
                502,
                duration,
                &conn_metadata,
                stream_id as u32,
            )
            .await;
            let resp = Response::builder().status(502).body(()).unwrap();
            stream.send_response(resp).await?;
            stream
                .send_data(Bytes::from(format!("upstream error: {}", e)))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    let status = resp.status().as_u16();
    let resp_headers = resp.headers().clone();
    let resp_ver = format_http_version(resp.version());

    // Collect response body and trailers (matching TCP path)
    let (resp_body_bytes, resp_trailers) = match resp.into_body().collect().await {
        Ok(collected) => {
            let trailers = collected.trailers().cloned();
            (collected.to_bytes(), trailers)
        }
        Err(e) => {
            error!("HTTP/3 upstream body collect error: {}", e);
            let duration = started.elapsed().as_millis() as u64;
            record_h3_error(
                &shared.captures,
                &client_id,
                method.as_str(),
                &uri_str,
                &req_headers,
                &req_body_bytes,
                502,
                duration,
                &conn_metadata,
                stream_id as u32,
            )
            .await;
            let resp = Response::builder().status(502).body(()).unwrap();
            stream.send_response(resp).await?;
            stream
                .send_data(Bytes::from(format!("upstream body error: {}", e)))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    let duration = started.elapsed().as_millis() as u64;

    // Build transaction for linting and capture
    let mut tx = crate::http_transaction::HttpTransaction::new(
        client_id.clone(),
        method.as_str().to_string(),
        uri_str.clone(),
    );
    tx.request.headers = req_headers.clone();
    tx.request.version = "HTTP/3".to_string();
    tx.request.body_length = Some(req_body_bytes.len() as u64);
    tx.request.trailers = req_trailers;
    tx.request_body = Some(req_body_bytes);

    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: resp_headers.clone(),
        body_length: Some(resp_body_bytes.len() as u64),
        trailers: resp_trailers,
    });
    tx.response_body = Some(resp_body_bytes.clone());
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };
    tx.connection_id = Some(conn_metadata.id);
    tx.sequence_number = Some(stream_id as u32);

    let violations = lint::lint_transaction(&tx, &shared.cfg, &shared.state, &shared.engine);
    tx.violations = violations;

    shared.state.record_transaction(&tx);
    let _ = shared.captures.write_transaction(&tx).await;

    // Send the response back over HTTP/3.
    // HTTP/3 has no hop-by-hop headers (RFC 9114 §4.2), but the upstream
    // response arrives via TCP and may contain them, so we still strip them.
    let mut resp_builder = Response::builder().status(status);
    let connection_hop_headers =
        parse_connection_tokens(resp_headers.get(hyper::header::CONNECTION));
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
            continue;
        }
        resp_builder = resp_builder.header(name, value);
    }
    let h3_resp = resp_builder.body(()).unwrap();
    stream.send_response(h3_resp).await?;
    stream.send_data(resp_body_bytes).await?;
    stream.finish().await?;

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
        for _ in 0..100 {
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
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
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
            for _ in 0..100 {
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
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
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
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: LegacyClient<_, http_body_util::Full<bytes::Bytes>> =
            LegacyClient::builder(TokioExecutor::new()).build(https);
        let state = StdArc::new(crate::state::StateStore::new(300, 10));
        let protocol_event_store = StdArc::new(
            crate::protocol_event_store::ProtocolEventStore::new(300, 100),
        );
        let engine = engine.unwrap_or_else(|| StdArc::new(crate::rules::RuleConfigEngine::new()));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            protocol_event_store,
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
        Ok(builder.body(boxed_empty())?)
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

    #[test]
    fn is_websocket_upgrade_detects_valid_upgrade() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn is_websocket_upgrade_case_insensitive() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "upgrade")
            .header("upgrade", "WebSocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[rstest]
    #[case(Some("keep-alive"), Some("websocket"), false)]
    #[case(Some("Upgrade"), None, false)]
    #[case(None, Some("websocket"), false)]
    #[case(None, None, false)]
    #[case(Some("Upgrade"), Some("h2c"), false)]
    fn is_websocket_upgrade_negative(
        #[case] connection: Option<&str>,
        #[case] upgrade: Option<&str>,
        #[case] expected: bool,
    ) {
        let mut builder = Request::builder()
            .method("GET")
            .uri("http://example.com/ws");
        if let Some(c) = connection {
            builder = builder.header("connection", c);
        }
        if let Some(u) = upgrade {
            builder = builder.header("upgrade", u);
        }
        let req = builder.body(Full::new(Bytes::new()).boxed()).unwrap();
        assert_eq!(is_websocket_upgrade(&req), expected);
    }

    #[test]
    fn message_to_info_text() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Text("hello".into());
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 1);
        assert_eq!(info.payload_length, 5);
        assert_eq!(info.direction, MessageDirection::Client);
    }

    #[test]
    fn message_to_info_binary() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Binary(vec![1, 2, 3].into());
        let info = message_to_info(&msg, MessageDirection::Server);
        assert_eq!(info.opcode, 2);
        assert_eq!(info.payload_length, 3);
        assert_eq!(info.direction, MessageDirection::Server);
    }

    #[test]
    fn message_to_info_ping_pong() {
        use crate::websocket_session::MessageDirection;
        let ping = tokio_tungstenite::tungstenite::Message::Ping(vec![0; 4].into());
        let info = message_to_info(&ping, MessageDirection::Client);
        assert_eq!(info.opcode, 9);
        assert_eq!(info.payload_length, 4);

        let pong = tokio_tungstenite::tungstenite::Message::Pong(vec![0; 2].into());
        let info = message_to_info(&pong, MessageDirection::Server);
        assert_eq!(info.opcode, 10);
        assert_eq!(info.payload_length, 2);
    }

    #[test]
    fn message_to_info_close_with_frame() {
        use crate::websocket_session::MessageDirection;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        let msg = tokio_tungstenite::tungstenite::Message::Close(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "bye".into(),
        }));
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 8);
        // 2 bytes for code + 3 bytes for "bye"
        assert_eq!(info.payload_length, 5);
    }

    #[test]
    fn message_to_info_close_without_frame() {
        use crate::websocket_session::MessageDirection;
        let msg = tokio_tungstenite::tungstenite::Message::Close(None);
        let info = message_to_info(&msg, MessageDirection::Server);
        assert_eq!(info.opcode, 8);
        assert_eq!(info.payload_length, 0);
    }

    #[tokio::test]
    async fn relay_websocket_relays_messages_and_captures_session() -> anyhow::Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        // Create two duplex pairs to simulate client<->proxy and proxy<->server
        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp = std::env::temp_dir().join(format!("lint_ws_relay_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        // Spawn the relay
        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                cw_clone,
                ProtocolLintCtx {
                    connection_id: uuid::Uuid::new_v4(),
                    store: std::sync::Arc::new(
                        crate::protocol_event_store::ProtocolEventStore::new(300, 100),
                    ),
                    cfg: std::sync::Arc::new(crate::config::Config::default()),
                    engine: std::sync::Arc::new(crate::rules::RuleConfigEngine::new()),
                },
            )
            .await;
        });

        // Client side: wrap in WebSocket (client role)
        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        // Server side: wrap in WebSocket (server role)
        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Client sends a text message
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "hello".into(),
            ))
            .await?;

        // Server should receive it
        let msg = server_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("hello".into())
        );

        // Server sends a response
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "world".into(),
            ))
            .await?;

        // Client should receive it
        let msg = client_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("world".into())
        );

        // Client sends close
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "done".into(),
                },
            )))
            .await?;

        // Server receives close and sends close back
        let msg = server_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Close(_)
        ));
        server_ws.close(None).await.ok();

        // Close client side
        client_ws.close(None).await.ok();

        // Wait for relay to finish
        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        // Flush captures
        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Read the capture file and verify the WebSocket session was written
        let content = tokio::fs::read_to_string(&p).await?;
        assert!(!content.is_empty(), "capture file should not be empty");
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));
        assert_eq!(
            session["transaction_id"].as_str(),
            Some(tx_id.to_string().as_str())
        );
        let messages = session["messages"].as_array().unwrap();
        assert!(messages.len() >= 2, "should have at least 2 messages");
        // First message should be client text
        assert_eq!(messages[0]["direction"].as_str(), Some("client"));
        assert_eq!(messages[0]["opcode"].as_u64(), Some(1));
        // Second message should be server text
        assert_eq!(messages[1]["direction"].as_str(), Some("server"));
        assert_eq!(messages[1]["opcode"].as_u64(), Some(1));
        // Should have a close code
        assert_eq!(session["close_code"].as_u64(), Some(1000));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_fails_without_host() {
        let uri: Uri = "/no-host".parse().unwrap();
        let result = connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_fails_with_closed_port() {
        // pick a port that's not listening
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse().unwrap();
        let result = connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_upstream_connect_error() -> anyhow::Result<()> {
        // Test that handle_websocket_upgrade returns 502 when upstream is unreachable
        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        // Build a request targeting a closed port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = l.local_addr()?.port();
        drop(l);

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        // Create a fake OnUpgrade that will never complete
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        assert_eq!(resp.status().as_u16(), 502);

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_non_101_response() -> anyhow::Result<()> {
        // Start a plain HTTP server that returns 400 for upgrade requests
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
                let _ = socket.try_write(resp);
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        // Server returned 400, so proxy should forward it
        assert_eq!(resp.status().as_u16(), 400);

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_server_initiated_close() -> anyhow::Result<()> {
        // Test the s2c direction: server sends close first
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp = std::env::temp_dir().join(format!("lint_ws_s2c_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                cw_clone,
                ProtocolLintCtx {
                    connection_id: uuid::Uuid::new_v4(),
                    store: std::sync::Arc::new(
                        crate::protocol_event_store::ProtocolEventStore::new(300, 100),
                    ),
                    cfg: std::sync::Arc::new(crate::config::Config::default()),
                    engine: std::sync::Arc::new(crate::rules::RuleConfigEngine::new()),
                },
            )
            .await;
        });

        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Server sends a message first
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "server-msg".into(),
            ))
            .await?;
        let msg = client_ws.next().await.unwrap()?;
        assert_eq!(
            msg,
            tokio_tungstenite::tungstenite::Message::Text("server-msg".into())
        );

        // Server initiates close
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "server-done".into(),
                },
            )))
            .await?;

        // Client receives close and responds
        let msg = client_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Close(_)
        ));
        // Send close response then drop to end the c2s stream
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .ok();
        drop(client_ws);
        drop(server_ws);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));
        // Close was from server direction
        assert_eq!(session["close_code"].as_u64(), Some(1000));
        let messages = session["messages"].as_array().unwrap();
        // Should have server text + server close + possibly client close
        assert!(messages.len() >= 2);

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_abrupt_disconnect() -> anyhow::Result<()> {
        // Test error path: client disconnects abruptly
        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_abrupt_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                cw_clone,
                ProtocolLintCtx {
                    connection_id: uuid::Uuid::new_v4(),
                    store: std::sync::Arc::new(
                        crate::protocol_event_store::ProtocolEventStore::new(300, 100),
                    ),
                    cfg: std::sync::Arc::new(crate::config::Config::default()),
                    engine: std::sync::Arc::new(crate::rules::RuleConfigEngine::new()),
                },
            )
            .await;
        });

        // Drop client and server immediately to simulate abrupt disconnect
        drop(client_side);
        drop(server_side);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Should still write a session record (with empty messages)
        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(session["type"].as_str(), Some("websocket_session"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[test]
    fn message_to_info_frame_variant() {
        use crate::websocket_session::MessageDirection;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::OpCode;
        use tokio_tungstenite::tungstenite::protocol::frame::{Frame, FrameHeader};
        let header = FrameHeader {
            is_final: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Data(
                tokio_tungstenite::tungstenite::protocol::frame::coding::Data::Text,
            ),
            mask: None,
        };
        let frame = Frame::from_payload(header, vec![b'h', b'i'].into());
        let msg = tokio_tungstenite::tungstenite::Message::Frame(frame);
        let info = message_to_info(&msg, MessageDirection::Client);
        assert_eq!(info.opcode, 1); // Text opcode
        assert_eq!(info.payload_length, 2);
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_plain_tcp_success() -> anyhow::Result<()> {
        // Start a simple HTTP server that accepts connections
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.try_write(resp);
            }
        });

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let (mut sender, _handle) =
            connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP).await?;

        // Verify we can send a request
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{}/ws", port))
            .body(Full::new(Bytes::new()))?;
        let resp = sender.send_request(req).await?;
        assert_eq!(resp.status().as_u16(), 200);

        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn h3_listen_without_tls_returns_error() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.general.h3_listen = Some("127.0.0.1:3443".to_string());
        // TLS is disabled by default

        let tmp = std::env::temp_dir().join(format!("lint_h3_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;
        let engine = StdArc::new(crate::rules::RuleConfigEngine::new());

        // Bind to an ephemeral port
        let listen: SocketAddr = "127.0.0.1:0".parse()?;
        let result = run_proxy_with_limit(listen, cw, StdArc::new(cfg), engine, Some(0)).await;

        // Should fail because h3_listen requires TLS
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("h3_listen requires TLS"));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_websocket_upgrade_path() -> anyhow::Result<()> {
        // Start a WebSocket echo server
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let ws_port = ws_listener.local_addr()?.port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = ws_listener.accept().await {
                tokio::spawn(async move {
                    let ws = tokio_tungstenite::accept_async(stream).await;
                    if let Ok(mut ws) = ws {
                        use futures_util::{SinkExt, StreamExt};
                        while let Some(Ok(msg)) = ws.next().await {
                            if msg.is_close() {
                                let _ = ws.close(None).await;
                                break;
                            }
                            let _ = ws.send(msg).await;
                        }
                    }
                });
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        // Build a WebSocket upgrade request with full URI
        let uri: Uri = format!("http://127.0.0.1:{}/ws", ws_port).parse()?;
        let ws_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            uuid::Uuid::new_v4().as_bytes(),
        );
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", ws_key)
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

        // Should get a 101 Switching Protocols response
        assert_eq!(resp.status().as_u16(), 101);
        // Verify upgrade headers are forwarded
        assert!(resp.headers().get("upgrade").is_some());

        // Give the relay task time to start and check captures
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let content = tokio::fs::read_to_string(&tmp).await?;
        assert!(!content.is_empty());
        // The 101 transaction should be recorded
        let first_line = content.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(first_line)?;
        assert_eq!(v["response"]["status"].as_u64(), Some(101));
        assert_eq!(v["was_upgraded"].as_bool(), Some(true));
        assert_eq!(v["upgrade_protocol"].as_str(), Some("websocket"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_send_request_error() -> anyhow::Result<()> {
        // Start a server that accepts TCP connections then immediately closes them
        // This will cause the hyper handshake to succeed but send_request to fail
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            // Accept connection then drop it immediately
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse()?;
        let upstream_req = Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))?;

        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let started = Instant::now();
        let client_id =
            crate::state::ClientIdentifier::new("127.0.0.1".parse().unwrap(), "test".to_string());

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &hyper::HeaderMap::new(),
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        // Server dropped connection, send_request should fail -> 502
        assert_eq!(resp.status().as_u16(), 502);

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_websocket_binary_and_ping_messages() -> anyhow::Result<()> {
        // Test relay with binary and ping/pong messages to cover more message_to_info paths
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_side, proxy_client_side) = tokio::io::duplex(4096);
        let (proxy_server_side, server_side) = tokio::io::duplex(4096);

        let tx_id = Uuid::new_v4();
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_binary_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let cw_clone = cw.clone();
        let relay_handle = tokio::spawn(async move {
            relay_websocket(
                proxy_client_side,
                proxy_server_side,
                tx_id,
                cw_clone,
                ProtocolLintCtx {
                    connection_id: uuid::Uuid::new_v4(),
                    store: std::sync::Arc::new(
                        crate::protocol_event_store::ProtocolEventStore::new(300, 100),
                    ),
                    cfg: std::sync::Arc::new(crate::config::Config::default()),
                    engine: std::sync::Arc::new(crate::rules::RuleConfigEngine::new()),
                },
            )
            .await;
        });

        let mut client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None)
                .await;

        let mut server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_side, Role::Server, None)
                .await;

        // Client sends binary
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![1, 2, 3].into(),
            ))
            .await?;
        let msg = server_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Binary(_)
        ));

        // Server sends binary back
        server_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![4, 5, 6].into(),
            ))
            .await?;
        let msg = client_ws.next().await.unwrap()?;
        assert!(matches!(
            msg,
            tokio_tungstenite::tungstenite::Message::Binary(_)
        ));

        // Client sends ping
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Ping(
                vec![7, 8].into(),
            ))
            .await?;

        // Server receives ping (may receive pong auto-response)
        let msg = server_ws.next().await.unwrap()?;
        assert!(
            matches!(msg, tokio_tungstenite::tungstenite::Message::Ping(_))
                || matches!(msg, tokio_tungstenite::tungstenite::Message::Pong(_))
        );

        // Close
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .ok();
        drop(client_ws);
        drop(server_ws);

        tokio::time::timeout(std::time::Duration::from_secs(5), relay_handle)
            .await
            .expect("relay did not finish")
            .expect("relay panicked");

        drop(cw);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = tokio::fs::read_to_string(&p).await?;
        let session: serde_json::Value = serde_json::from_str(content.trim())?;
        let messages = session["messages"].as_array().unwrap();
        // Should have binary c2s, binary s2c, ping, and close messages
        assert!(messages.len() >= 3);

        // Verify binary opcode (2) appears
        assert!(messages.iter().any(|m| m["opcode"].as_u64() == Some(2)));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_non_ws_101_marks_upgrade() -> anyhow::Result<()> {
        // A non-WebSocket request to an upstream that returns 101 should mark
        // the transaction as upgraded with the appropriate protocol.
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
                let _ = socket.write_all(resp).await;
                // Keep connection open briefly for hyper to process the 101
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        // Regular GET — NOT a WebSocket upgrade request
        let uri: Uri = format!("http://127.0.0.1:{}/upgrade", port).parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_http_logic(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            ),
        )
        .await??;

        // The LegacyClient should forward the 101 response and the proxy
        // should mark the transaction as upgraded.
        assert_eq!(resp.status().as_u16(), 101);
        // Upgrade and Connection headers must be preserved for 101 responses
        assert_eq!(
            resp.headers().get("upgrade").and_then(|v| v.to_str().ok()),
            Some("h2c")
        );
        assert!(resp.headers().get("connection").is_some());

        let content = tokio::fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(content.lines().next().unwrap())?;
        assert_eq!(v["was_upgraded"].as_bool(), Some(true));
        assert_eq!(v["upgrade_protocol"].as_str(), Some("h2c"));

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_with_quic_connection_metadata() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/quic-test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, None).await?;

        let req = make_request_with_headers("GET", format!("{}/quic-test", mock.uri()), None)?;

        // Use QUIC connection metadata to verify it flows through handle_request
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new_quic(
            "127.0.0.1:12345".parse()?,
        ));
        assert_eq!(
            conn_metadata.transport,
            crate::connection::TransportProtocol::Quic,
        );

        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = read_capture(&tmp).await?;
        assert!(!entries.is_empty());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }
}
