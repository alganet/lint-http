// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The WebSocket upgrade handshake: dial the origin, send the client's
//! handshake, record the transaction, and hand a completed upgrade to the
//! relay.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{debug, error};

use crate::proxy::exchange::record_error_transaction;
use crate::proxy::hop_by_hop::format_http_version;
use crate::proxy::{boxed_full, BoxError, ResponseBody, Shared};

use super::relay::relay_websocket;
use super::{accepted_extensions, without_extension_negotiation};

/// Handle a WebSocket upgrade request: connect directly to upstream, relay
/// frames via tokio-tungstenite, and capture the session.
#[allow(clippy::too_many_arguments)]
pub(in crate::proxy) async fn handle_websocket_upgrade(
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
) -> Result<Response<ResponseBody>, Infallible> {
    // Connect directly to upstream with upgrade support, reusing the shared
    // outbound TLS config (loaded once at startup).
    let (mut sender, _conn_handle) =
        match connect_upstream_for_upgrade(uri, scheme, &shared.upstream.tls_config).await {
            Ok(s) => s,
            Err(e) => {
                error!("websocket upstream connect error: {}", e);
                record_handshake_failure(
                    &shared,
                    client_id,
                    method,
                    uri_str,
                    req_headers,
                    req_version,
                    &body_bytes,
                    &conn_metadata,
                    started,
                )
                .await;
                return Ok(upstream_error_response(&e));
            }
        };

    // Send the upgrade request to the upstream server
    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("websocket upstream request error: {}", e);
            record_handshake_failure(
                &shared,
                client_id,
                method,
                uri_str,
                req_headers,
                req_version,
                &body_bytes,
                &conn_metadata,
                started,
            )
            .await;
            return Ok(upstream_error_response(&e));
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
        // A 101 has no body; a non-101 response body streams through to the
        // client but is not captured here, so record it as unknown rather than
        // falsely claiming zero length.
        //
        // The `Some(0)` is knowledge, not a guess -- the sentence below is what
        // makes zero the only possible answer for a 101, and it is why the two
        // arms are asymmetric. `None` here means "we did not look"; `Some(0)`
        // means "there is nothing to look at". Only one of those can be said
        // without reading the body, and only for 1xx.
        //
        // cite(RFC 9110 § 15.2): "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers."
        body_length: if status == 101 { Some(0) } else { None },
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

    let tx_id = tx.id;

    if status == 101 {
        shared.pipeline().commit(tx).await;

        // Extract the server-side upgraded IO
        let server_upgraded = hyper::upgrade::on(&mut upstream_resp);

        // Build the 101 response to send back to the client.
        // Forward ALL headers including upgrade-related ones (Connection, Upgrade,
        // Sec-WebSocket-Accept) — do NOT strip hop-by-hop headers for 101. The one
        // exception is the extension negotiation, which stops at the relay:
        // see `without_extension_negotiation`. The capture above already
        // recorded the 101 as received.
        let mut resp_builder = Response::builder().status(101);
        for (name, value) in without_extension_negotiation(&headers).iter() {
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(boxed_full(Bytes::new()))
            .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new())));

        // Spawn the background relay, holding a connection permit and a shutdown
        // token for its lifetime: the permit counts the live session against
        // `max_connections` (and makes the drain barrier wait for it), the token
        // lets it close promptly on shutdown. The permit is best-effort —
        // an already-upgraded connection can't be rejected if we're at capacity.
        let captures_clone = shared.captures.clone();
        let connection_id = conn_metadata.id;
        let pe_pipeline = shared.protocol_event_pipeline();
        let relay_permit = shared.semaphore.clone().try_acquire_owned().ok();
        if relay_permit.is_none() {
            debug!("websocket relay starting without a connection permit (at capacity)");
        }
        let relay_shutdown = shared.shutdown.clone();
        let negotiated = accepted_extensions(&headers);
        tokio::spawn(async move {
            let _relay_permit = relay_permit;
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
                connection_id,
                negotiated,
                pe_pipeline,
                relay_shutdown,
            )
            .await;
        });

        Ok(resp)
    } else {
        // Upstream did not accept the upgrade: it is a normal HTTP response.
        // Stream it back to the client (no buffering, no over-limit 502) and
        // commit the handshake transaction. The non-101 response body is not
        // separately captured here (as before — only the handshake metadata is
        // recorded), so a plain streaming forward suffices.
        shared.pipeline().commit(tx).await;

        let inner = upstream_resp
            .into_body()
            .map_err(|e| -> BoxError { e.into() })
            .boxed_unsync();
        let mut resp_builder = Response::builder().status(status);
        for (name, value) in
            crate::proxy::exchange::filter_response_headers(&headers, status).iter()
        {
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(inner)
            .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new())));

        Ok(resp)
    }
}

/// Build the 502 returned to the client when a WebSocket upstream handshake
/// fails (connect or request-send error), through the one shared error-response
/// builder.
fn upstream_error_response(e: impl std::fmt::Display) -> Response<ResponseBody> {
    crate::proxy::exchange::into_response(crate::proxy::exchange::error_response(
        502,
        format!("websocket upstream error: {}", e),
    ))
}

/// Record a transaction for a WebSocket handshake that failed before the
/// upstream produced any response, so the request is not silently lost. Routes
/// through the pipeline (lint → state → capture) and consumes one sequence
/// number, matching the success path.
#[allow(clippy::too_many_arguments)]
async fn record_handshake_failure(
    shared: &Arc<Shared>,
    client_id: &crate::state::ClientIdentifier,
    method: &Method,
    uri_str: &str,
    req_headers: &hyper::HeaderMap,
    req_version: &str,
    body_bytes: &Bytes,
    conn_metadata: &crate::connection::ConnectionMetadata,
    started: &Instant,
) {
    let duration = started.elapsed().as_millis() as u64;
    record_error_transaction(
        shared,
        client_id,
        method.as_str(),
        uri_str,
        req_headers,
        req_version,
        502,
        None,
        duration,
        Some(body_bytes.clone()),
        conn_metadata.id,
        conn_metadata.next_sequence_number(),
        false,
        false,
    )
    .await;
}

/// Open a direct TCP (or TLS) connection to the upstream host and perform
/// an HTTP/1.1 handshake with upgrade support.
///
/// `fallback_scheme` is used only when the URI itself has no scheme set
/// (origin-form requests).  An absolute-form URI's own scheme always wins,
/// so the scheme used for TLS and the default port can never disagree with
/// what's in the URI.
async fn connect_upstream_for_upgrade(
    uri: &Uri,
    fallback_scheme: &hyper::http::uri::Scheme,
    tls_config: &Arc<rustls::ClientConfig>,
) -> anyhow::Result<(
    hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
)> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in URI"))?;
    let scheme = uri.scheme().unwrap_or(fallback_scheme);
    let is_https = *scheme == hyper::http::uri::Scheme::HTTPS;
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

    let tcp = tokio::net::TcpStream::connect((host, port)).await?;

    if is_https {
        // The trust store was loaded once at startup; reuse the shared config
        // (an `Arc` bump) instead of re-reading native certs per upgrade.
        let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::test_support::make_shared_with_cfg;
    use std::sync::Arc as StdArc;

    /// A trust-store-free client config for the `ws://` (non-TLS) tests below —
    /// they never reach the HTTPS branch, so an empty root store is fine.
    fn test_tls_config() -> StdArc<rustls::ClientConfig> {
        StdArc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    /// Whether a captured transaction's request headers (serialized as ordered
    /// `[name, value]` pairs) contain `name`.
    fn captured_request_has_header(v: &serde_json::Value, name: &str) -> bool {
        v["request"]["headers"]
            .as_array()
            .map(|pairs| pairs.iter().any(|p| p[0] == name))
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_fails_without_host() {
        let uri: Uri = "/no-host".parse().unwrap();
        let result =
            connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP, &test_tls_config())
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_upstream_for_upgrade_fails_with_closed_port() {
        // pick a port that's not listening
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let uri: Uri = format!("http://127.0.0.1:{}/ws", port).parse().unwrap();
        let result =
            connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP, &test_tls_config())
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_websocket_upgrade_upstream_connect_error() -> anyhow::Result<()> {
        // Test that handle_websocket_upgrade returns 502 when upstream is unreachable
        let cfg = StdArc::new(crate::config::Config::default());
        let (shared, tmp, cw) = make_shared_with_cfg(cfg, None).await?;

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
        let mut req_headers = hyper::HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &req_headers,
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        assert_eq!(resp.status().as_u16(), 502);

        // The failed handshake is now captured rather than silently dropped,
        // preserving the request headers.
        cw.flush().await?;
        let content = tokio::fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(502));
        assert!(
            captured_request_has_header(&v, "x-test"),
            "captured request should preserve request headers"
        );

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
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None).await?;

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
    async fn handle_websocket_upgrade_non_101_streams_response() -> anyhow::Result<()> {
        // Plain HTTP server rejecting the upgrade with a body larger than the
        // old `max_body_bytes` guard — it must now stream through (no 502).
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

        let mut cfg = crate::config::Config::default();
        cfg.general.max_body_bytes = 4;
        let (shared, tmp, _cw) = make_shared_with_cfg(StdArc::new(cfg), None).await?;

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

        // The upstream's non-101 status and body stream through unchanged — no 502.
        assert_eq!(resp.status().as_u16(), 400);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Bad Request");

        // The handshake transaction is captured with the upstream's real status.
        _cw.flush().await?;
        let content = tokio::fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(400));
        assert_eq!(v["response_body_over_limit"].as_bool(), Some(false));

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
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
            connect_upstream_for_upgrade(&uri, &hyper::http::uri::Scheme::HTTP, &test_tls_config())
                .await?;

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
        let (shared, tmp, cw) = make_shared_with_cfg(cfg, None).await?;

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
        let mut req_headers = hyper::HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let resp = handle_websocket_upgrade(
            upstream_req,
            fake_on_upgrade,
            &uri,
            &hyper::http::uri::Scheme::HTTP,
            &started,
            &client_id,
            &Method::GET,
            &uri.to_string(),
            &req_headers,
            "HTTP/1.1",
            Bytes::new(),
            None,
            shared,
            conn_metadata,
        )
        .await?;

        // Server dropped connection, send_request should fail -> 502
        assert_eq!(resp.status().as_u16(), 502);

        // The failed handshake is captured rather than silently dropped.
        cw.flush().await?;
        let content = tokio::fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(content.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(502));
        assert!(
            captured_request_has_header(&v, "x-test"),
            "captured request should preserve request headers"
        );

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }
}
