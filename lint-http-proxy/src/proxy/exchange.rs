// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Transport-agnostic request-handling core shared by the H1/H2 and H3
//! handlers.
//!
//! Each transport's handler does its own front half — reading the request and
//! its body in protocol-specific ways — then hands a [`ProxiedRequest`] to
//! [`exchange`], which forwards upstream, collects the response, builds and
//! commits the [`HttpTransaction`], and returns a [`ProxiedResponse`] the
//! transport delivers in its own way. This keeps lint coverage, capture, and
//! header handling identical across protocols instead of relying on two copies
//! staying in sync.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, Uri};
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{error, warn};
use uuid::Uuid;

use crate::state::ClientIdentifier;

use super::body::{collect_limited, CollectLimitedError};
use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::Shared;

/// The post-front-half request inputs both transports compute, ready for the
/// shared upstream exchange.
pub(super) struct ProxiedRequest {
    pub method: Method,
    /// Absolute URI used for the upstream request line.
    pub uri: Uri,
    /// Value recorded in `tx.request.uri` — the transport's original request
    /// target (H1 keeps the possibly origin-form `req.uri()`; not `uri`).
    pub uri_str: String,
    /// Original client request headers; suppression is applied only when
    /// building the upstream request.
    pub headers: HeaderMap,
    /// Request version string ("HTTP/1.1", "HTTP/3", …).
    pub version: String,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
    pub client_id: ClientIdentifier,
    pub connection_id: Uuid,
    pub sequence_number: u32,
}

/// What the transport should deliver to the client. Headers are already
/// hop-by-hop filtered (with the 101 carve-out); they are empty for
/// proxy-generated error responses.
pub(super) struct ProxiedResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Forward `req` upstream, collect the response, build + commit the
/// transaction, and return the response to deliver. Internal errors (upstream
/// failure, over-limit / failed response body, request build failure) are
/// recorded directly to captures (bypassing lint/state, as before) and turned
/// into a proxy error `ProxiedResponse`.
pub(super) async fn exchange(
    req: ProxiedRequest,
    shared: &Arc<Shared>,
    started: Instant,
) -> ProxiedResponse {
    let max_body_bytes = shared.cfg.general.max_body_bytes;

    let upstream_req =
        match build_upstream_request(&req.method, &req.uri, &req.headers, &req.body, shared) {
            Ok(r) => r,
            Err(e) => {
                error!("failed to build upstream request: {}", e);
                let duration = started.elapsed().as_millis() as u64;
                record_exchange_error(shared, &req, 500, None, duration, false).await;
                return error_response(500, format!("request build error: {}", e));
            }
        };

    let resp = match shared.client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            let duration = started.elapsed().as_millis() as u64;
            record_exchange_error(shared, &req, 502, None, duration, false).await;
            return error_response(502, format!("upstream error: {}", e));
        }
    };

    let status = resp.status().as_u16();
    let upstream_headers = resp.headers().clone();
    let resp_ver = format_http_version(resp.version());

    let (resp_body_bytes, resp_trailers) =
        match collect_limited(resp.into_body(), max_body_bytes).await {
            Ok((bytes, trailers)) => (bytes, trailers),
            Err(CollectLimitedError::OverLimit) => {
                warn!(
                    "upstream response body exceeds max_body_bytes ({})",
                    max_body_bytes
                );
                let duration = started.elapsed().as_millis() as u64;
                // Record the upstream's real status and headers; the body was
                // discarded, so only the over-limit marker explains its absence.
                record_exchange_error(
                    shared,
                    &req,
                    status,
                    Some(upstream_headers.clone()),
                    duration,
                    true,
                )
                .await;
                return error_response(502, "upstream response exceeds max_body_bytes".to_string());
            }
            Err(CollectLimitedError::Other(e)) => {
                error!("upstream body collect error: {}", e);
                let duration = started.elapsed().as_millis() as u64;
                record_exchange_error(shared, &req, 500, None, duration, false).await;
                return error_response(500, format!("upstream body collect error: {}", e));
            }
        };

    let duration = started.elapsed().as_millis() as u64;

    // Read everything the client response needs from the upstream headers
    // before they are moved into the recorded transaction below.
    let out_headers = filter_response_headers(&upstream_headers, status);
    let (was_upgraded, upgrade_protocol) = if status == 101 {
        let proto = upstream_headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        (true, proto)
    } else {
        (false, None)
    };

    let mut tx = crate::http_transaction::HttpTransaction::new(
        req.client_id,
        req.method.as_str().to_string(),
        req.uri_str,
    );
    tx.request.headers = req.headers;
    tx.request.version = req.version;
    tx.request.body_length = Some(req.body.len() as u64);
    tx.request.trailers = req.trailers;
    tx.request_body = Some(req.body);

    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: resp_ver,
        headers: upstream_headers,
        body_length: Some(resp_body_bytes.len() as u64),
        trailers: resp_trailers,
    });
    tx.response_body = Some(resp_body_bytes.clone());
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: duration,
    };
    tx.connection_id = Some(req.connection_id);
    tx.sequence_number = Some(req.sequence_number);
    tx.was_upgraded = was_upgraded;
    tx.upgrade_protocol = upgrade_protocol;

    shared.pipeline().commit(tx).await;

    ProxiedResponse {
        status,
        headers: out_headers,
        body: resp_body_bytes,
    }
}

/// Build the upstream request, copying client headers except those configured
/// in `suppress_headers`.
pub(super) fn build_upstream_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
    shared: &Arc<Shared>,
) -> Result<Request<Full<Bytes>>, hyper::http::Error> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers.iter() {
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
    builder.body(Full::new(body.clone()))
}

/// Filter response headers before returning them to the client. For 101
/// Switching Protocols all headers are preserved (the Connection/Upgrade
/// headers are essential to the handshake); otherwise hop-by-hop headers are
/// stripped. `append` preserves repeated headers (e.g. `set-cookie`).
pub(super) fn filter_response_headers(headers: &HeaderMap, status: u16) -> HeaderMap {
    if status == 101 {
        return headers.clone();
    }
    let connection_hop_headers = parse_connection_tokens(headers.get(hyper::header::CONNECTION));
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop_header(&name_str, &connection_hop_headers) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn error_response(status: u16, body: String) -> ProxiedResponse {
    ProxiedResponse {
        status,
        headers: HeaderMap::new(),
        body: Bytes::from(body),
    }
}

/// Record an error transaction from inside [`exchange`], where the full
/// [`ProxiedRequest`] is in hand. The request body has already been collected,
/// so `request_body_over_limit` is always `false` here.
async fn record_exchange_error(
    shared: &Arc<Shared>,
    req: &ProxiedRequest,
    status: u16,
    response_headers: Option<HeaderMap>,
    duration_ms: u64,
    response_body_over_limit: bool,
) {
    record_error_transaction(
        shared,
        &req.client_id,
        req.method.as_str(),
        &req.uri_str,
        &req.headers,
        &req.version,
        status,
        response_headers,
        duration_ms,
        Some(req.body.clone()),
        req.connection_id,
        req.sequence_number,
        false,
        response_body_over_limit,
    )
    .await;
}

/// Build a minimal `HttpTransaction` (request + response status only) and route
/// it through the full pipeline (lint → state record → capture), so error
/// exchanges are linted and enter `TransactionHistory` like any other traffic.
/// Used on the error paths where the upstream exchange never completes
/// normally. Shared by both transports; the caller supplies the transport's
/// version string, connection id, and sequence number.
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_error_transaction(
    shared: &Arc<Shared>,
    client_id: &ClientIdentifier,
    method: &str,
    uri_str: &str,
    req_headers: &HeaderMap,
    version: &str,
    status: u16,
    response_headers: Option<HeaderMap>,
    duration_ms: u64,
    req_body: Option<Bytes>,
    connection_id: Uuid,
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
    tx.request.version = version.to_string();
    if let Some(b) = req_body {
        tx.request.body_length = Some(b.len() as u64);
        tx.request_body = Some(b);
    }
    tx.request_body_over_limit = request_body_over_limit;
    tx.response_body_over_limit = response_body_over_limit;
    tx.response = Some(crate::http_transaction::ResponseInfo {
        status,
        version: version.to_string(),
        headers: response_headers.unwrap_or_default(),
        body_length: None,
        trailers: None,
    });
    tx.timing = crate::http_transaction::TimingInfo { duration_ms };
    tx.connection_id = Some(connection_id);
    tx.sequence_number = Some(sequence_number);
    // Lint, record to state, and capture — error exchanges are real traffic.
    shared.pipeline().commit(tx).await;
}
