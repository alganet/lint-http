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
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Request, Uri};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{error, warn};
use uuid::Uuid;

use crate::state::ClientIdentifier;

use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::tee_body::{self, CapturedBody};
use super::{boxed_full, BoxError, ClientBody, ResponseBody, Shared};

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
    /// The request body, already wrapped so it streams to the upstream while a
    /// bounded prefix is teed for capture (H3 wraps a buffered body).
    pub body: ClientBody,
    /// Resolves with the teed request-body capture (prefix, total length,
    /// trailers) once the body has finished streaming to the upstream.
    pub body_done: oneshot::Receiver<CapturedBody>,
    pub client_id: ClientIdentifier,
    pub connection_id: Uuid,
    pub sequence_number: u32,
}

/// What the transport should deliver to the client. Headers are already
/// hop-by-hop filtered (with the 101 carve-out); they are empty for
/// proxy-generated error responses. The body streams: for a successful
/// exchange it tees a bounded prefix into the transaction (committed at
/// stream-end); for a proxy error it is the buffered error message.
pub(super) struct ProxiedResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: ResponseBody,
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
    let ProxiedRequest {
        method,
        uri,
        uri_str,
        headers,
        version,
        body,
        body_done,
        client_id,
        connection_id,
        sequence_number,
    } = req;

    let upstream_req = match build_upstream_request(&method, &uri, &headers, body, shared) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to build upstream request: {}", e);
            let duration = started.elapsed().as_millis() as u64;
            record_exchange_error(
                shared,
                &client_id,
                method.as_str(),
                &uri_str,
                &headers,
                &version,
                connection_id,
                sequence_number,
                500,
                None,
                duration,
                body_done.await.ok().as_ref(),
            )
            .await;
            return error_response(500, format!("request build error: {}", e));
        }
    };

    // Choose the upstream transport at this single seam: HTTP/3 when the origin
    // authority is on the H3 allowlist (capability-driven, opt-in), else the
    // hyper H1/H2 client. Both branches yield a `Response<ResponseBody>` so the
    // tee/commit machinery below is identical; the H3 branch stamps the response
    // version as HTTP/3, which is what lands in `tx.response.version`.
    let h3_client = uri.authority().and_then(|a| {
        shared
            .upstream
            .h3
            .as_ref()
            .filter(|h3| h3.handles(a.as_str()))
    });
    let resp: Result<hyper::Response<ResponseBody>, String> = if let Some(h3) = h3_client {
        h3.forward(upstream_req).await.map_err(|e| e.to_string())
    } else {
        shared
            .upstream
            .client
            .request(upstream_req)
            .await
            .map(|r| r.map(|b| b.map_err(|e| -> BoxError { e.into() }).boxed_unsync()))
            .map_err(|e| e.to_string())
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            let duration = started.elapsed().as_millis() as u64;
            record_exchange_error(
                shared,
                &client_id,
                method.as_str(),
                &uri_str,
                &headers,
                &version,
                connection_id,
                sequence_number,
                502,
                None,
                duration,
                body_done.await.ok().as_ref(),
            )
            .await;
            return error_response(502, format!("upstream error: {}", e));
        }
    };

    let status = resp.status().as_u16();
    let upstream_headers = resp.headers().clone();
    let resp_ver = format_http_version(resp.version());

    // Status, headers, and upgrade info are known immediately. The body streams
    // to the client unbuffered while `TeeBody` copies a bounded prefix and sums
    // the real total; the transaction is committed once the stream ends.
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

    let prefix_cap = shared.cfg.general.captures_max_body_bytes;
    // Already a `ResponseBody` from both upstream branches above.
    let inner = resp.into_body();
    let (resp_body, done_rx) = tee_body::tee(inner, prefix_cap);

    // Commit once both body halves have finished streaming — the request body
    // (already sent upstream) and the response body (just read by the client) —
    // so each `body_length` reflects the real total and each captured body is a
    // bounded prefix.
    let shared = shared.clone();
    tokio::spawn(async move {
        let (req_cap, resp_cap) = tokio::join!(body_done, done_rx);
        let (Ok(req_cap), Ok(resp_cap)) = (req_cap, resp_cap) else {
            // A tee was dropped without finalizing (should not happen — Drop
            // always sends). Surface it so a lost capture is diagnosable.
            warn!(
                connection_id = %connection_id,
                sequence_number, "dropped transaction: body capture never resolved"
            );
            return;
        };
        let mut tx = crate::http_transaction::HttpTransaction::new(
            client_id,
            method.as_str().to_string(),
            uri_str,
        );
        tx.request.headers = headers;
        tx.request.version = version;
        tx.request.body_length = Some(req_cap.total);
        tx.request.trailers = req_cap.trailers;
        tx.request_body = Some(req_cap.prefix);
        tx.request_body_over_limit = req_cap.truncated;

        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: resp_ver,
            headers: upstream_headers,
            body_length: Some(resp_cap.total),
            trailers: resp_cap.trailers,
        });
        tx.response_body = Some(resp_cap.prefix);
        tx.response_body_over_limit = resp_cap.truncated;
        tx.timing = crate::http_transaction::TimingInfo {
            duration_ms: started.elapsed().as_millis() as u64,
        };
        tx.connection_id = Some(connection_id);
        tx.sequence_number = Some(sequence_number);
        tx.was_upgraded = was_upgraded;
        tx.upgrade_protocol = upgrade_protocol;

        shared.pipeline().commit(tx).await;
    });

    ProxiedResponse {
        status,
        headers: out_headers,
        body: resp_body,
    }
}

/// Build the upstream request line + headers (method, URI, client headers minus
/// `suppress_headers`), leaving the body for the caller to attach — the exchange
/// path uses a boxed [`ClientBody`], the WebSocket path a raw `Full<Bytes>` for
/// its own upgrade connection.
///
/// When `strip_hop_by_hop` is set, RFC 9110 §7.6.1 hop-by-hop request headers
/// (and any header the client names in `Connection:`) are dropped instead of
/// relayed to the origin — the request-side mirror of [`filter_response_headers`].
/// The WebSocket path passes `false`: its handshake relies on `Connection` /
/// `Upgrade` reaching the upstream, exactly as the response side preserves them
/// for a `101`.
pub(super) fn upstream_request_builder(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    shared: &Arc<Shared>,
    strip_hop_by_hop: bool,
) -> hyper::http::request::Builder {
    let mut builder = Request::builder().method(method).uri(uri);
    let connection_hop_headers = if strip_hop_by_hop {
        parse_connection_tokens(headers.get(hyper::header::CONNECTION))
    } else {
        std::collections::HashSet::new()
    };
    for (name, value) in headers.iter() {
        // `HeaderName::as_str()` is already lowercase, so it can be matched
        // against the (lowercase) hop-by-hop set directly without normalizing.
        let name_str = name.as_str();
        if strip_hop_by_hop && is_hop_by_hop_header(name_str, &connection_hop_headers) {
            continue;
        }
        if shared
            .cfg
            .tls
            .suppress_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name_str))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
}

pub(super) fn build_upstream_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: ClientBody,
    shared: &Arc<Shared>,
) -> Result<Request<ClientBody>, hyper::http::Error> {
    upstream_request_builder(method, uri, headers, shared, true).body(body)
}

/// Filter response headers before returning them to the client. For 101
/// Switching Protocols all headers are preserved (the Connection/Upgrade
/// headers are essential to the handshake); otherwise hop-by-hop headers are
/// stripped. `append` preserves repeated headers (e.g. `set-cookie`).
pub(super) fn filter_response_headers(headers: &HeaderMap, status: u16) -> HeaderMap {
    // Why 101 escapes the hop-by-hop strip below: Upgrade is a connection-specific
    // field an intermediary would normally remove, and a 101 is the one response
    // that cannot survive losing it.
    // cite(RFC 9110 § 15.2.2): "The 101 (Switching Protocols) status code indicates that the server understands and is willing to comply with the client's request, via the Upgrade header field"
    if status == 101 {
        return headers.clone();
    }
    let connection_hop_headers = parse_connection_tokens(headers.get(hyper::header::CONNECTION));
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        // `HeaderName::as_str()` is already lowercase (no normalization needed).
        if is_hop_by_hop_header(name.as_str(), &connection_hop_headers) {
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
        body: boxed_full(Bytes::from(body)),
    }
}

/// Record an error transaction from inside [`exchange`] (build / upstream
/// failure), using whatever request-body prefix the tee captured before the
/// request was dropped.
#[allow(clippy::too_many_arguments)]
async fn record_exchange_error(
    shared: &Arc<Shared>,
    client_id: &ClientIdentifier,
    method: &str,
    uri_str: &str,
    headers: &HeaderMap,
    version: &str,
    connection_id: Uuid,
    sequence_number: u32,
    status: u16,
    response_headers: Option<HeaderMap>,
    duration_ms: u64,
    req_captured: Option<&CapturedBody>,
) {
    record_error_transaction(
        shared,
        client_id,
        method,
        uri_str,
        headers,
        version,
        status,
        response_headers,
        duration_ms,
        req_captured.map(|c| c.prefix.clone()),
        connection_id,
        sequence_number,
        req_captured.is_some_and(|c| c.truncated),
        false,
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
