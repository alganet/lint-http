// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP proxy server implementation with request forwarding and capture.

use crate::capture::{CaptureRecordBuilder, CaptureWriter};
use crate::config::Config;
use crate::lint;

use crate::ca::CertificateAuthority;
use hyper::upgrade::Upgraded;
use hyper::{service::service_fn, Body, Client, Method, Request, Response, Server, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{error, info};

struct AlwaysResolves(Arc<CertifiedKey>);

impl ResolvesServerCert for AlwaysResolves {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Shared {
    client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    state: Arc<crate::state::StateStore>,
    ca: Option<Arc<CertificateAuthority>>,
}

pub async fn run_proxy(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
) -> anyhow::Result<()> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, Body> = Client::builder().build(https);

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
                    state.seed_from_capture(record);
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
    });

    let make_svc =
        hyper::service::make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
            let shared = shared.clone();
            let remote_addr = conn.remote_addr();
            let conn_metadata = Arc::new(crate::connection::ConnectionMetadata::new(remote_addr));

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_request(
                        req,
                        shared.clone(),
                        conn_metadata.clone(),
                        Uri::from_static("http://dummy").scheme().unwrap().clone(),
                    )
                }))
            }
        });

    let server = Server::try_bind(&listen)?.serve(make_svc);
    info!(%listen, "listening");
    server.await?;
    Ok(())
}

async fn handle_request(
    req: Request<Body>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<Body>, Infallible> {
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
                    Err(e) => error!("upgrade error: {}", e),
                }
            });
            return Ok(Response::new(Body::empty()));
        } else {
            return Ok(Response::builder()
                .status(405)
                .body(Body::from("CONNECT not supported (TLS disabled)"))
                .unwrap());
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
                .body(Body::from(pem))
                .unwrap());
        } else {
            return Ok(Response::builder()
                .status(404)
                .body(Body::from("TLS not enabled"))
                .unwrap());
        }
    }

    handle_http_logic(req, shared, conn_metadata, scheme).await
}

async fn handle_inner_request(
    req: Request<Body>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(Response::builder()
            .status(405)
            .body(Body::from("Nested CONNECT not supported"))
            .unwrap());
    }
    handle_http_logic(req, shared, conn_metadata, scheme).await
}

async fn handle_http_logic(
    req: Request<Body>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();

    // Build upstream URI: if incoming URI is absolute, use it; otherwise use Host header
    let uri = if req.uri().scheme().is_some() {
        req.uri().clone()
    } else {
        // build from Host header
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

    // Build upstream request
    let mut builder = Request::builder().method(req.method()).uri(uri.clone());
    // copy headers
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

    // capture method/uri/headers before moving request
    let method = req.method().clone();
    let uri_str = req.uri().to_string();
    let req_headers = req.headers().clone();

    // Extract client identifier
    // Use the captured remote address from connection metadata
    let client_ip = conn_metadata.remote_addr.ip();
    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let client_id = crate::state::ClientIdentifier::new(client_ip, user_agent);

    let body = req.into_body();

    // capture references for error handling
    let client = &shared.client;
    let captures = &shared.captures;

    let upstream_req = match builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to build upstream request: {}", e);
            let body = Body::from(format!("request build error: {}", e));
            let resp = Response::builder()
                .status(500)
                .body(body)
                .unwrap_or_else(|_| Response::new(Body::from("internal error")));
            // record a failed capture with 500
            let duration = started.elapsed().as_millis() as u64;
            let _ = captures
                .write_capture(
                    CaptureRecordBuilder::new(method.as_str(), &uri_str, 500, &req_headers)
                        .duration_ms(duration),
                )
                .await;
            return Ok(resp);
        }
    };
    let resp = match client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            let body = Body::from(format!("upstream error: {}", e));
            let resp = Response::builder()
                .status(502)
                .body(body)
                .unwrap_or_else(|_| Response::new(Body::from("upstream error")));
            // record capture with error status
            let duration = started.elapsed().as_millis() as u64;
            let _ = captures
                .write_capture(
                    CaptureRecordBuilder::new(method.as_str(), &uri_str, 502, &req_headers)
                        .duration_ms(duration),
                )
                .await;
            return Ok(resp);
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    let duration = started.elapsed().as_millis() as u64;

    // Evaluate lint rules using config
    let mut violations = lint::lint_request(
        &client_id,
        &uri_str,
        &method,
        &req_headers,
        &conn_metadata,
        &shared.cfg,
        &shared.state,
    );
    violations.extend(lint::lint_response(
        &client_id,
        &uri_str,
        status,
        &headers,
        &conn_metadata,
        &shared.cfg,
        &shared.state,
    ));

    // Record transaction in state for future analysis
    shared
        .state
        .record_transaction(&client_id, &uri_str, status, &headers);
    shared.state.record_connection(&client_id, &conn_metadata);

    // Write capture (we don't capture bodies in MVP)
    let _ = captures
        .write_capture(
            CaptureRecordBuilder::new(method.as_str(), &uri_str, status, &req_headers)
                .response_headers(&headers)
                .duration_ms(duration)
                .violations(violations.clone()),
        )
        .await;

    // Attach a header with lint summary (for demo)
    let mut resp = resp;
    if !violations.is_empty() {
        let s = violations
            .iter()
            .map(|v| v.rule.clone())
            .collect::<Vec<_>>()
            .join(",");
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&s) {
            resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-lint-violations"),
                hv,
            );
        }
    }

    Ok(resp)
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

    let ca = shared.ca.as_ref().unwrap();
    let cert = ca.gen_cert_for_domain(host)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolves(cert)));

    // Configure ALPN to support HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let stream = acceptor.accept(client_conn).await?;

    let service = service_fn(move |req| {
        let shared = shared.clone();
        let conn_metadata = conn_metadata.clone();
        let fut: Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>> =
            Box::pin(async move {
                handle_inner_request(req, shared, conn_metadata, hyper::http::uri::Scheme::HTTPS)
                    .await
            });
        fut
    });

    if let Err(e) = hyper::server::conn::Http::new()
        .http2_only(false)
        .serve_connection(stream, service)
        .await
    {
        error!("TLS connection error: {}", e);
    }

    Ok(())
}

async fn tunnel(mut upgraded: Upgraded, host: &str, port: u16) -> std::io::Result<()> {
    let mut server = tokio::net::TcpStream::connect((host, port)).await?;
    let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};
    use std::sync::Arc as StdArc;
    use tokio::fs;
    use uuid::Uuid;
    use wiremock::MockServer;
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handle_request_forwards_and_captures() {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let tmp = std::env::temp_dir().join(format!("lint_proxy_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None,
        });

        let uri: Uri = mock.uri().parse().expect("parse uri");
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert!(resp.headers().get("x-lint-violations").is_some());

        let s = fs::read_to_string(&tmp).await.expect("read capture");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse jsonl");
        assert_eq!(v["status"].as_u64().unwrap(), 200);

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn handle_request_upstream_error() {
        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_err_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None,
        });

        // Use a port that is (likely) closed to provoke a client error
        let req = Request::builder()
            .method("GET")
            .uri("http://127.0.0.1:9/")
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 502);

        let s = fs::read_to_string(&tmp).await.expect("read capture");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse jsonl");
        assert_eq!(v["status"].as_u64().unwrap(), 502);

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn handle_request_with_relative_uri_builds_from_host() {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rel"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_rel_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None,
        });

        // Build a relative URI and set Host header so proxy builds absolute URI from Host
        let host = mock.address().to_string();
        let req = Request::builder()
            .method("GET")
            .uri("/rel")
            .header(hyper::header::HOST, host)
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);

        let s = fs::read_to_string(&tmp).await.expect("read capture");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse jsonl");
        assert_eq!(v["status"].as_u64().unwrap(), 200);

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn handle_request_no_violations_does_not_set_header() {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("cache-control", "max-age=1")
                    .insert_header("etag", "W/\"1\"")
                    .insert_header("x-content-type-options", "nosniff")
                    .set_body_string("ok"),
            )
            .mount(&mock)
            .await;

        let tmp = std::env::temp_dir().join(format!("lint_proxy_nv_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None,
        });

        let uri: Uri = format!("{}/ok", mock.uri()).parse().expect("parse uri");
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("user-agent", "test-agent")
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert!(resp.headers().get("x-lint-violations").is_none());

        let s = fs::read_to_string(&tmp).await.expect("read capture");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse jsonl");
        assert_eq!(v["status"].as_u64().unwrap(), 200);

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn run_proxy_bind_fails_when_port_taken() {
        // Bind a socket first to reserve the port
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = l.local_addr().expect("local addr");

        let tmp = std::env::temp_dir().join(format!(
            "lint-http_proxy_bind_test_{}.jsonl",
            Uuid::new_v4()
        ));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");
        let cfg = StdArc::new(crate::config::Config::default());

        // run_proxy should return an error since the port is already in use
        let res = run_proxy(addr, cw, cfg).await;
        assert!(res.is_err());

        let _ = fs::remove_file(&tmp).await;
        drop(l);
    }

    #[tokio::test]
    async fn run_proxy_starts_and_can_be_aborted() {
        let tmp =
            std::env::temp_dir().join(format!("lint-http_proxy_run_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, cw, cfg).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        task.abort();
        let _ = task.await;

        let _ = tokio::fs::remove_file(&tmp).await;
    }
    #[tokio::test]
    async fn handle_request_serves_ca_cert() {
        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_cert_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        let cfg = StdArc::new(cfg);

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));

        // Create a temporary CA for the test
        let ca_dir = std::env::temp_dir().join(format!("lint_http_test_ca_{}", Uuid::new_v4()));
        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("create ca");

        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: Some(ca),
        });

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-x509-ca-cert"
        );

        let body_bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("BEGIN CERTIFICATE"));

        let _ = fs::remove_file(&tmp).await;
        let _ = fs::remove_dir_all(&ca_dir).await;
    }

    #[tokio::test]
    async fn handle_request_connect_without_tls_returns_405() {
        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_connect_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default()); // TLS disabled by default
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));

        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None, // No CA because TLS is disabled
        });

        // Try to use CONNECT method
        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();

        // Should return 405 because TLS is disabled
        assert_eq!(resp.status().as_u16(), 405);

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn handle_request_ca_cert_endpoint_without_tls_returns_404() {
        let tmp =
            std::env::temp_dir().join(format!("lint_proxy_nocert_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default()); // TLS disabled by default
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, Body> = Client::builder().build(https);
        let state = StdArc::new(crate::state::StateStore::new(300));

        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
            state,
            ca: None,
        });

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Body::empty())
            .unwrap();

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse().unwrap(),
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await
        .unwrap();

        // Should return 404 because TLS is not enabled
        assert_eq!(resp.status().as_u16(), 404);

        let _ = fs::remove_file(&tmp).await;
    }
}
