// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/1.1 and HTTP/2 request dispatch and forwarding.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Method, Request, Response, Uri};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::error;

use crate::capture::CaptureWriter;
use crate::lint;

use super::connect::handle_connect;
use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::websocket::{handle_websocket_upgrade, is_websocket_upgrade};
use super::Shared;

pub(super) async fn handle_request<B>(
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

pub(super) async fn handle_inner_request<B>(
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

/// Build a minimal `HttpTransaction` (request + response status only) and
/// write it to the captures file.  Used on the error paths in
/// [`handle_http_logic`] where the upstream request never completes normally.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use crate::proxy::test_support::{
        make_request_with_headers, make_shared_with_cfg, read_capture,
    };
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use std::sync::Arc as StdArc;
    use tokio::fs;
    use uuid::Uuid;
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let parsed = crate::proxy::hop_by_hop::parse_connection_tokens(Some(
            &HeaderValue::from_static("keep-alive, Foo ,"),
        ));
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("foo"));
        assert!(crate::proxy::hop_by_hop::parse_connection_tokens(Some(
            &HeaderValue::from_static(" , ,a,b")
        ))
        .contains("a"));

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
}
