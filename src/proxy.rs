// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP proxy server implementation with request forwarding and capture.

use crate::capture::CaptureWriter;
use crate::config::Config;
use crate::lint;
use hyper::{service::service_fn, Body, Client, Request, Response, Server, Uri};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{error, info};

struct Shared {
    client: Client<hyper::client::HttpConnector>,
    captures: CaptureWriter,
    cfg: Arc<Config>,
}

pub async fn run_proxy(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
) -> anyhow::Result<()> {
    let client: Client<hyper::client::HttpConnector> = Client::new();
    let shared = Arc::new(Shared {
        client,
        captures,
        cfg,
    });

    let make_svc = hyper::service::make_service_fn(move |_conn| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| handle_request(req, shared.clone()))) }
    });

    let server = Server::try_bind(&listen)?.serve(make_svc);
    info!(%listen, "listening");
    server.await?;
    Ok(())
}

async fn handle_request(
    req: Request<Body>,
    shared: Arc<Shared>,
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
        let s = format!("http://{}{}", host, path);
        s.parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("http://localhost/"))
    };

    // Build upstream request
    let mut builder = Request::builder().method(req.method()).uri(uri.clone());
    // copy headers
    for (name, value) in req.headers().iter() {
        builder = builder.header(name, value);
    }

    // capture method/uri/headers before moving request
    let method = req.method().clone();
    let uri_str = req.uri().to_string();
    let req_headers = req.headers().clone();

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
                    method.as_str(),
                    &uri_str,
                    500_u16,
                    None,
                    duration,
                    &req_headers,
                    vec![],
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
                    method.as_str(),
                    &uri_str,
                    502_u16,
                    None,
                    duration,
                    &req_headers,
                    vec![],
                )
                .await;
            return Ok(resp);
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    let duration = started.elapsed().as_millis() as u64;

    // Evaluate lint rules using config
    let mut violations = lint::lint_request(&method, &req_headers, &shared.cfg);
    violations.extend(lint::lint_response(status, &headers, &shared.cfg));

    // Write capture (we don't capture bodies in MVP)
    let _ = captures
        .write_capture(
            method.as_str(),
            &uri_str,
            status,
            Some(&headers),
            duration,
            &req_headers,
            violations.clone(),
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

        let tmp = std::env::temp_dir().join(format!("patina_proxy_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let client = Client::new();
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
        });

        let uri: Uri = mock.uri().parse().expect("parse uri");
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let resp = handle_request(req, shared.clone()).await.unwrap();
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
            std::env::temp_dir().join(format!("patina_proxy_err_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let client = Client::new();
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
        });

        // Use a port that is (likely) closed to provoke a client error
        let req = Request::builder()
            .method("GET")
            .uri("http://127.0.0.1:9/")
            .body(Body::empty())
            .unwrap();

        let resp = handle_request(req, shared.clone()).await.unwrap();
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
            std::env::temp_dir().join(format!("patina_proxy_rel_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let client = Client::new();
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
        });

        // Build a relative URI and set Host header so proxy builds absolute URI from Host
        let host = mock.address().to_string();
        let req = Request::builder()
            .method("GET")
            .uri("/rel")
            .header(hyper::header::HOST, host)
            .body(Body::empty())
            .unwrap();

        let resp = handle_request(req, shared.clone()).await.unwrap();
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

        let tmp =
            std::env::temp_dir().join(format!("patina_proxy_nv_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();
        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let cfg = StdArc::new(crate::config::Config::default());
        let client = Client::new();
        let shared = StdArc::new(Shared {
            client,
            captures: cw.clone(),
            cfg,
        });

        let uri: Uri = format!("{}/ok", mock.uri()).parse().expect("parse uri");
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("user-agent", "test-agent")
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();

        let resp = handle_request(req, shared.clone()).await.unwrap();
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

        let tmp =
            std::env::temp_dir().join(format!("lint-http_proxy_bind_test_{}.jsonl", Uuid::new_v4()));
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
}
