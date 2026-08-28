// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The WebSocket upgrade handshake: dial the origin, send the client's
//! handshake, record the transaction, and hand a completed upgrade to the
//! relay.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, Uri};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{debug, error, warn};

use crate::proxy::exchange::{
    assemble_transaction, error_response, into_response, record_error_transaction,
    upstream_request_builder, ErrorFacts, RequestFacts, ResponseFacts,
};
use crate::proxy::hop_by_hop::format_http_version;
use crate::proxy::{boxed_full, BoxError, ResponseBody, Shared};

use super::relay::relay_websocket;
use super::{accepted_extensions, without_extension_negotiation};

/// Everything the transport front half hands the WebSocket upgrade path.
pub(in crate::proxy) struct WsUpgradeRequest {
    pub facts: RequestFacts,
    /// Absolute URI used for the upstream request line and dial.
    pub uri: Uri,
    /// Scheme used only when the URI itself carries none (origin-form
    /// requests).
    pub fallback_scheme: hyper::http::uri::Scheme,
    /// The buffered handshake body (DoS-guarded by `max_body_bytes`).
    pub body: Bytes,
    pub trailers: Option<hyper::HeaderMap>,
    /// The client half of the upgrade, extracted before the body was consumed.
    pub client_on_upgrade: hyper::upgrade::OnUpgrade,
}

/// Handle a WebSocket upgrade request: connect directly to upstream, relay
/// frames via tokio-tungstenite, and capture the session.
pub(in crate::proxy) async fn handle_websocket_upgrade(
    req: WsUpgradeRequest,
    shared: Arc<Shared>,
    started: Instant,
) -> Result<Response<ResponseBody>, Infallible> {
    let WsUpgradeRequest {
        facts,
        uri,
        fallback_scheme,
        body: body_bytes,
        trailers: req_trailers,
        client_on_upgrade,
    } = req;

    // Refuse new upgrades at capacity, before dialing the origin. The relay
    // session that would follow outlives this request handler, so it must hold
    // its own permit to stay inside `max_connections` and the shutdown drain
    // barrier — and a permit that must be held has to be acquired while the
    // upgrade can still be refused. An explicit 503 here is the honest answer
    // a best-effort, uncounted session was not.
    let relay_permit = match shared.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            warn!("websocket upgrade refused: proxy at max_connections capacity");
            record_error_transaction(
                &shared,
                &facts,
                ErrorFacts {
                    status: 503,
                    duration_ms: started.elapsed().as_millis() as u64,
                    req_body: Some(body_bytes.clone()),
                    ..Default::default()
                },
            )
            .await;
            return Ok(into_response(error_response(
                503,
                "websocket upgrade refused: proxy at connection capacity".to_string(),
            )));
        }
    };

    // Build the upstream handshake request. Preserve hop-by-hop headers: the
    // WebSocket upgrade depends on `Connection`/`Upgrade` reaching the origin
    // (the request-side analog of the 101 carve-out in
    // `filter_response_headers`). The one field removed is the extension
    // negotiation, which stops at the relay — the frames of an accepted
    // extension would be unreadable in the middle, and a session tungstenite
    // cannot read is a session it kills. The capture records `facts.headers`
    // as received, offer included; see
    // `websocket::without_extension_negotiation`.
    let upstream_headers = without_extension_negotiation(&facts.headers);
    let upstream_req =
        match upstream_request_builder(&facts.method, &uri, &upstream_headers, &shared, false)
            .body(Full::new(body_bytes.clone()))
        {
            Ok(r) => r,
            Err(e) => {
                error!("failed to build upstream request: {}", e);
                record_error_transaction(
                    &shared,
                    &facts,
                    ErrorFacts {
                        status: 500,
                        duration_ms: started.elapsed().as_millis() as u64,
                        req_body: Some(body_bytes.clone()),
                        ..Default::default()
                    },
                )
                .await;
                return Ok(into_response(error_response(
                    500,
                    format!("request build error: {}", e),
                )));
            }
        };

    // Connect directly to upstream with upgrade support, reusing the shared
    // outbound TLS config (loaded once at startup).
    let mut sender =
        match connect_upstream_for_upgrade(&uri, &fallback_scheme, &shared.upstream.tls_config)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                error!("websocket upstream connect error: {}", e);
                record_handshake_failure(&shared, &facts, &body_bytes, started).await;
                return Ok(upstream_error_response(&e));
            }
        };

    // Send the upgrade request to the upstream server
    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("websocket upstream request error: {}", e);
            record_handshake_failure(&shared, &facts, &body_bytes, started).await;
            return Ok(upstream_error_response(&e));
        }
    };

    let status = upstream_resp.status().as_u16();
    let headers = upstream_resp.headers().clone();
    let resp_ver = format_http_version(upstream_resp.version());
    let duration = started.elapsed().as_millis() as u64;

    // Record the HTTP transaction (the 101 handshake) through the shared
    // assembly, adding the buffered request body this path alone captures.
    let mut tx = assemble_transaction(
        &facts,
        ResponseFacts {
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
        },
        duration,
    );
    tx.request.body_length = Some(body_bytes.len() as u64);
    tx.request.trailers = req_trailers;
    tx.request_body = Some(body_bytes);

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

        // Spawn the background relay, holding the connection permit acquired
        // before the dial and a shutdown token for its lifetime: the permit
        // counts the live session against `max_connections` (and makes the
        // drain barrier wait for it), the token lets it close promptly on
        // shutdown.
        let connection_id = facts.connection_id;
        let pe_pipeline = shared.protocol_event_pipeline();
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
/// through the pipeline (lint → state → capture) with the request's one
/// sequence number, matching the success path.
async fn record_handshake_failure(
    shared: &Arc<Shared>,
    facts: &RequestFacts,
    body_bytes: &Bytes,
    started: Instant,
) {
    record_error_transaction(
        shared,
        facts,
        ErrorFacts {
            status: 502,
            duration_ms: started.elapsed().as_millis() as u64,
            req_body: Some(body_bytes.clone()),
            ..Default::default()
        },
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
) -> anyhow::Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
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
        Ok(handshake_and_drive(tls_stream).await?)
    } else {
        Ok(handshake_and_drive(tcp).await?)
    }
}

/// hyper HTTP/1.1 handshake over `io`, driving the connection (with upgrade
/// support) in a background task whose end is observed: a driver error is
/// logged with its cause rather than vanishing with a dropped JoinHandle.
async fn handshake_and_drive<T>(
    io: T,
) -> hyper::Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!(error = %e, "websocket upstream connection driver ended with error");
        }
    });
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::test_support::make_shared_with_cfg;
    use hyper::Request;
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

    /// The request facts the handshake tests share: a GET from one test
    /// client, carrying the headers under test.
    fn test_facts(uri: &Uri, headers: hyper::HeaderMap) -> RequestFacts {
        RequestFacts {
            method: hyper::Method::GET,
            uri_str: uri.to_string(),
            headers,
            version: "HTTP/1.1".to_string(),
            client_id: crate::state::ClientIdentifier::new(
                "127.0.0.1".parse().unwrap(),
                "test".to_string(),
            ),
            connection_id: uuid::Uuid::new_v4(),
            sequence_number: 0,
        }
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
        // Create a fake OnUpgrade that will never complete
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let started = Instant::now();
        let mut req_headers = hyper::HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let resp = handle_websocket_upgrade(
            WsUpgradeRequest {
                facts: test_facts(&uri, req_headers),
                uri: uri.clone(),
                fallback_scheme: hyper::http::uri::Scheme::HTTP,
                body: Bytes::new(),
                trailers: None,
                client_on_upgrade: fake_on_upgrade,
            },
            shared,
            started,
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
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let started = Instant::now();

        let resp = handle_websocket_upgrade(
            WsUpgradeRequest {
                facts: test_facts(&uri, hyper::HeaderMap::new()),
                uri: uri.clone(),
                fallback_scheme: hyper::http::uri::Scheme::HTTP,
                body: Bytes::new(),
                trailers: None,
                client_on_upgrade: fake_on_upgrade,
            },
            shared,
            started,
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
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let started = Instant::now();

        let resp = handle_websocket_upgrade(
            WsUpgradeRequest {
                facts: test_facts(&uri, hyper::HeaderMap::new()),
                uri: uri.clone(),
                fallback_scheme: hyper::http::uri::Scheme::HTTP,
                body: Bytes::new(),
                trailers: None,
                client_on_upgrade: fake_on_upgrade,
            },
            shared,
            started,
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
        let mut sender =
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
        let fake_on_upgrade = hyper::upgrade::on(
            Request::builder()
                .method("GET")
                .uri("http://fake/")
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        );

        let started = Instant::now();
        let mut req_headers = hyper::HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let resp = handle_websocket_upgrade(
            WsUpgradeRequest {
                facts: test_facts(&uri, req_headers),
                uri: uri.clone(),
                fallback_scheme: hyper::http::uri::Scheme::HTTP,
                body: Bytes::new(),
                trailers: None,
                client_on_upgrade: fake_on_upgrade,
            },
            shared,
            started,
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
