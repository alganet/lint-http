// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/3 (QUIC) accept loop and per-stream request handling.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, Uri};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::ca::CertificateAuthority;
use crate::capture::CaptureWriter;

use super::connect::AlwaysResolves;
use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::Shared;

/// QUIC transport parameter defaults for the HTTP/3 proxy.
///
/// These are chosen to be reasonable for HTTP/3 usage per RFC 9114 / RFC 9000
/// §18.2.  The values are recorded in a [`QuicTransportParameters`] so they
/// can be emitted as protocol events and validated by lint rules.
const QUIC_MAX_CONCURRENT_BIDI_STREAMS: u64 = 256;
const QUIC_MAX_CONCURRENT_UNI_STREAMS: u64 = 8;
const QUIC_MAX_IDLE_TIMEOUT_MS: u64 = 30_000;
const QUIC_STREAM_RECEIVE_WINDOW: u64 = 1_048_576; // 1 MiB
const QUIC_RECEIVE_WINDOW: u64 = 4_194_304; // 4 MiB

/// Create a QUIC endpoint bound to `addr` with a TLS certificate for
/// `server_name`.  This performs all fallible initialization (cert generation,
/// socket bind) synchronously so errors propagate to the caller.
pub(super) fn init_h3_endpoint(
    addr: SocketAddr,
    server_name: &str,
    ca: &CertificateAuthority,
) -> anyhow::Result<(
    quinn::Endpoint,
    crate::protocol_event::QuicTransportParameters,
)> {
    let cert = ca.gen_cert_for_domain(server_name)?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolves::new(cert)));
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("failed to build QUIC server config: {}", e))?;

    // Build an explicit TransportConfig so we know exactly what parameters
    // the server advertises to clients.
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(
            quinn::VarInt::from_u64(QUIC_MAX_CONCURRENT_BIDI_STREAMS)
                .expect("bidi streams fits VarInt"),
        )
        .max_concurrent_uni_streams(
            quinn::VarInt::from_u64(QUIC_MAX_CONCURRENT_UNI_STREAMS)
                .expect("uni streams fits VarInt"),
        )
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_millis(
                QUIC_MAX_IDLE_TIMEOUT_MS,
            ))
            .expect("idle timeout fits"),
        ))
        .stream_receive_window(
            quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW)
                .expect("stream receive window fits VarInt"),
        )
        .receive_window(
            quinn::VarInt::from_u64(QUIC_RECEIVE_WINDOW).expect("receive window fits VarInt"),
        );

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    let params = crate::protocol_event::QuicTransportParameters {
        initial_max_streams_bidi: Some(QUIC_MAX_CONCURRENT_BIDI_STREAMS),
        initial_max_data: Some(QUIC_RECEIVE_WINDOW),
        max_idle_timeout_ms: Some(QUIC_MAX_IDLE_TIMEOUT_MS),
        initial_max_stream_data_bidi_local: Some(QUIC_STREAM_RECEIVE_WINDOW),
        initial_max_stream_data_bidi_remote: Some(QUIC_STREAM_RECEIVE_WINDOW),
        initial_max_stream_data_uni: Some(QUIC_STREAM_RECEIVE_WINDOW),
    };

    info!(%addr, "HTTP/3 (QUIC) listening");
    Ok((endpoint, params))
}

/// Accept loop for an already-bound QUIC endpoint.  Each incoming connection
/// is handled in a spawned task through the same pipeline as TCP traffic.
/// Returns when `shutdown` is cancelled (or the endpoint stops yielding), after
/// asking the endpoint to close and waiting for in-flight connections to idle,
/// bounded by `shutdown_timeout_seconds`.
pub(super) async fn run_h3_accept_loop(
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    shutdown: CancellationToken,
) {
    loop {
        let incoming = tokio::select! {
            _ = shutdown.cancelled() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
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

    // Stop accepting, signal peers, and let in-flight connections drain.
    endpoint.close(0u32.into(), b"shutting down");
    let drain = std::time::Duration::from_secs(shared.cfg.general.shutdown_timeout_seconds);
    let _ = tokio::time::timeout(drain, endpoint.wait_idle()).await;
}

/// Handle a single HTTP/3 connection: accept request streams, forward upstream,
/// lint, capture, and return responses.
async fn handle_h3_connection(
    conn: quinn::Connection,
    shared: Arc<Shared>,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let conn_metadata = Arc::new(crate::connection::ConnectionMetadata::new_quic(remote_addr));
    let connection_id = conn_metadata.id;

    // Build an event sink so the frame-level observer inside the
    // InstrumentedConnection can emit protocol events (SETTINGS,
    // MAX_PUSH_ID) that are otherwise consumed internally by h3.
    let sink: crate::h3_instrument::EventSink = {
        let shared = shared.clone();
        Arc::new(move |kind| {
            emit_h3_protocol_event(kind, connection_id, &shared);
        })
    };

    let instrumented =
        crate::h3_instrument::InstrumentedConnection::new(h3_quinn::Connection::new(conn), sink);
    let mut h3_conn = h3::server::Connection::new(instrumented).await?;

    // Emit the QUIC transport parameters that this server advertised
    // during the handshake, so protocol-level rules can validate them.
    if let Some(ref params) = shared.quic_transport_params {
        emit_h3_protocol_event(
            crate::protocol_event::ProtocolEventKind::QuicTransportParams {
                params: params.clone(),
            },
            connection_id,
            &shared,
        );
    }

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
    let violations = shared.protocol_event_pipeline().commit(&pe);
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

    // Collect the request body from the h3 stream, bounded by max_body_bytes.
    let max_body_bytes = shared.cfg.general.max_body_bytes;
    let mut req_body = Vec::new();
    let mut req_body_over_limit = false;
    'collect: while let Some(chunk) = stream.recv_data().await? {
        let mut buf = chunk;
        if req_body.len() + buf.remaining() > max_body_bytes {
            req_body_over_limit = true;
            break 'collect;
        }
        while buf.has_remaining() {
            let bytes = buf.chunk();
            req_body.extend_from_slice(bytes);
            let len = bytes.len();
            buf.advance(len);
        }
    }
    if req_body_over_limit {
        warn!(
            "HTTP/3 request body exceeds max_body_bytes ({})",
            max_body_bytes
        );
        let duration = started.elapsed().as_millis() as u64;
        record_h3_error(
            &shared.captures,
            &client_id,
            method.as_str(),
            &uri_str,
            &req_headers,
            None,
            413,
            None,
            duration,
            &conn_metadata,
            stream_id as u32,
            true,
            false,
        )
        .await;
        let resp = Response::builder().status(413).body(()).unwrap();
        stream.send_response(resp).await?;
        stream
            .send_data(Bytes::from("request body exceeds max_body_bytes"))
            .await?;
        stream.finish().await?;
        return Ok(());
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
        req_body: Option<&Bytes>,
        status: u16,
        resp_headers: Option<&hyper::HeaderMap>,
        duration_ms: u64,
        conn_metadata: &crate::connection::ConnectionMetadata,
        sequence_number: u32,
        request_body_over_limit: bool,
        response_body_over_limit: bool,
    ) {
        let mut tx = crate::http_transaction::HttpTransaction::new(
            client_id.clone(),
            method.to_string(),
            uri_str.to_string(),
        );
        tx.request.headers = req_headers.clone();
        tx.request.version = "HTTP/3".to_string();
        if let Some(b) = req_body {
            tx.request.body_length = Some(b.len() as u64);
            tx.request_body = Some(b.clone());
        }
        tx.request_body_over_limit = request_body_over_limit;
        tx.response_body_over_limit = response_body_over_limit;
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/3".into(),
            headers: resp_headers.cloned().unwrap_or_default(),
            body_length: None,
            trailers: None,
        });
        tx.timing = crate::http_transaction::TimingInfo { duration_ms };
        tx.connection_id = Some(conn_metadata.id);
        tx.sequence_number = Some(sequence_number);
        if let Err(e) = captures.write_transaction(tx).await {
            warn!(error = %e, "failed to write transaction capture");
        }
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
                Some(&req_body_bytes),
                502,
                None,
                duration,
                &conn_metadata,
                stream_id as u32,
                false,
                false,
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

    // Collect response body and trailers (matching TCP path), bounded by
    // max_body_bytes.
    let (resp_body_bytes, resp_trailers) =
        match super::body::collect_limited(resp.into_body(), max_body_bytes).await {
            Ok((bytes, trailers)) => (bytes, trailers),
            Err(super::body::CollectLimitedError::OverLimit) => {
                warn!(
                    "HTTP/3 upstream response body exceeds max_body_bytes ({})",
                    max_body_bytes
                );
                let duration = started.elapsed().as_millis() as u64;
                // Record the upstream's real status and headers; the
                // over-limit marker explains the missing body.
                record_h3_error(
                    &shared.captures,
                    &client_id,
                    method.as_str(),
                    &uri_str,
                    &req_headers,
                    Some(&req_body_bytes),
                    status,
                    Some(&resp_headers),
                    duration,
                    &conn_metadata,
                    stream_id as u32,
                    false,
                    true,
                )
                .await;
                let resp = Response::builder().status(502).body(()).unwrap();
                stream.send_response(resp).await?;
                stream
                    .send_data(Bytes::from("upstream response exceeds max_body_bytes"))
                    .await?;
                stream.finish().await?;
                return Ok(());
            }
            Err(super::body::CollectLimitedError::Other(e)) => {
                error!("HTTP/3 upstream body collect error: {}", e);
                let duration = started.elapsed().as_millis() as u64;
                record_h3_error(
                    &shared.captures,
                    &client_id,
                    method.as_str(),
                    &uri_str,
                    &req_headers,
                    Some(&req_body_bytes),
                    502,
                    None,
                    duration,
                    &conn_metadata,
                    stream_id as u32,
                    false,
                    false,
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

    shared.pipeline().commit(tx).await;

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
mod tests {
    use crate::capture::CaptureWriter;
    use crate::proxy::http::handle_request;
    use crate::proxy::run_proxy_with_limit;
    use crate::proxy::test_support::{
        make_request_with_headers, make_shared_with_cfg, read_capture,
    };
    use std::net::SocketAddr;
    use std::sync::Arc as StdArc;
    use tokio::fs;
    use uuid::Uuid;
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

        // Bind to an ephemeral port
        let listen: SocketAddr = "127.0.0.1:0".parse()?;
        let result = run_proxy_with_limit(listen, cw, StdArc::new(cfg), Some(0)).await;

        // Should fail because h3_listen requires TLS
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("h3_listen requires TLS"));

        let _ = fs::remove_file(&tmp).await;
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
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None).await?;

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

        _cw.flush().await?;
        let entries = read_capture(&tmp).await?;
        assert!(!entries.is_empty());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }
}
