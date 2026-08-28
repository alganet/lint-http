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
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::state::ClientIdentifier;

use super::hop_by_hop::{format_http_version, is_hop_by_hop_header, parse_connection_tokens};
use super::tee_body::{self, CapturedBody};
use super::upstream_h3::H3Failure;
use super::{boxed_full, BoxError, ClientBody, ResponseBody, Shared};

/// The request-side facts every transaction record needs: computed once by the
/// transport front half, consumed by the exchange, the WebSocket handshake,
/// and every error path.
pub(super) struct RequestFacts {
    pub method: Method,
    /// Value recorded in `tx.request.uri` — the transport's original request
    /// target (H1 keeps the possibly origin-form `req.uri()`).
    pub uri_str: String,
    /// Original client request headers; suppression is applied only when
    /// building the upstream request.
    pub headers: HeaderMap,
    /// Request version string ("HTTP/1.1", "HTTP/3.0", …).
    pub version: String,
    pub client_id: ClientIdentifier,
    pub connection_id: Uuid,
    pub sequence_number: u32,
}

/// The post-front-half request inputs both transports compute, ready for the
/// shared upstream exchange.
pub(super) struct ProxiedRequest {
    pub facts: RequestFacts,
    /// Absolute URI used for the upstream request line.
    pub uri: Uri,
    /// The request body, already wrapped so it streams to the upstream while a
    /// bounded prefix is teed for capture (H3 wraps a buffered body).
    pub body: ClientBody,
    /// Resolves with the teed request-body capture (prefix, total length,
    /// trailers) once the body has finished streaming to the upstream.
    pub body_done: oneshot::Receiver<CapturedBody>,
}

/// What the transport should deliver to the client. Headers are already
/// hop-by-hop filtered (with the 101 carve-out); proxy-generated error
/// responses carry only a `Content-Type`. The body streams: for a successful
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
        facts,
        uri,
        body,
        body_done,
    } = req;

    let upstream_req =
        match build_upstream_request(&facts.method, &uri, &facts.headers, body, shared) {
            Ok(r) => r,
            Err(e) => {
                error!("failed to build upstream request: {}", e);
                let duration = started.elapsed().as_millis() as u64;
                record_exchange_error(shared, &facts, 500, duration, body_done.await.ok().as_ref())
                    .await;
                return error_response(500, format!("request build error: {}", e));
            }
        };

    // Choose the upstream transport at this single seam: HTTP/3 when the origin
    // authority is on the H3 allowlist (capability-driven, opt-in) and not
    // currently negative-cached, else the hyper H1/H2 client. Both branches
    // yield a `Response<ResponseBody>` so the tee/commit machinery below is
    // identical; the H3 branch stamps the response version as HTTP/3, which is
    // what lands in `tx.response.version` (a fall-back records its real version).
    let h3_target = uri.authority().and_then(|a| {
        let authority = a.as_str();
        let h3 = shared.upstream.h3.as_ref()?;
        if h3.is_suppressed(authority) {
            debug!(%authority, "h3 upstream suppressed by negative cache; using H1/H2");
            return None;
        }
        h3.route_for(authority)
            .map(|route| (h3, authority.to_string(), route))
    });
    if h3_target.is_none() {
        if let Some(a) = uri.authority() {
            // Only interesting when H3 is configured at all; otherwise this is
            // the ordinary H1/H2 path and not worth a line per request.
            if shared.upstream.h3.is_some() {
                debug!(authority = %a, "no h3 route for origin; using H1/H2");
            }
        }
    }
    let resp: Result<hyper::Response<ResponseBody>, String> = if let Some((h3, authority, route)) =
        h3_target
    {
        debug!(%authority, "forwarding upstream over HTTP/3");
        match h3.forward(upstream_req, &route, shared).await {
            Ok(r) => {
                h3.record_success(&authority);
                Ok(r)
            }
            Err(H3Failure::Retryable {
                error,
                request,
                pre_request,
            }) => {
                // A connect/handshake failure marks the origin as not currently
                // reachable over H3. Fall back to H1/H2 when it is safe: always
                // for a pre-request failure (nothing reached the origin), else
                // only for an idempotent method (RFC 9110 §9.2.2) — a header-sent
                // failure of a non-idempotent method must not be blindly retried.
                if pre_request {
                    h3.record_failure(&authority);
                }
                if pre_request || facts.method.is_idempotent() {
                    warn!(%authority, error = %error, "h3 upstream unavailable; falling back to H1/H2");
                    forward_via_hyper(shared, *request).await
                } else {
                    Err(format!(
                        "h3 upstream error (non-idempotent, not retried): {error}"
                    ))
                }
            }
            Err(H3Failure::Consumed { error }) => {
                // Request bytes were in flight with no response; the streaming
                // body cannot be replayed, so surface the failure as-is.
                Err(format!("h3 upstream error: {error}"))
            }
            Err(H3Failure::ResponseTimeout { error, replay }) => match replay {
                // A slow (not unreachable) origin: the request was fully sent but
                // no head came in time. Retry an idempotent bodyless request on
                // H1/H2; do *not* negative-cache — the origin is healthy, just
                // slow, and suppressing H3 would punish it. Anything else 502s.
                Some(request) => {
                    warn!(%authority, error = %error, "h3 upstream response-head timeout; retrying idempotent request via H1/H2");
                    forward_via_hyper(shared, *request).await
                }
                None => Err(format!("h3 upstream response timed out: {error}")),
            },
        }
    } else {
        forward_via_hyper(shared, upstream_req).await
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            let duration = started.elapsed().as_millis() as u64;
            record_exchange_error(shared, &facts, 502, duration, body_done.await.ok().as_ref())
                .await;
            return error_response(502, format!("upstream error: {}", e));
        }
    };

    let status = resp.status().as_u16();
    let upstream_headers = resp.headers().clone();
    let resp_ver = format_http_version(resp.version());

    // Feed any `Alt-Svc` advertisement (seen on whichever leg served this
    // response) into the H3 discovery cache, so a later request to this origin
    // can opportunistically use H3 (RFC 7838 / RFC 9114 §3.1.1).
    if let Some(h3) = shared.upstream.h3.as_ref() {
        if let Some(a) = uri.authority() {
            h3.record_alt_svc(a.as_str(), a.host(), &upstream_headers);
        }
    }

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
    let RequestFacts {
        method,
        uri_str,
        headers,
        version,
        client_id,
        connection_id,
        sequence_number,
    } = facts;
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

/// Send `req` through the hyper H1/H2 client, boxing its response body into the
/// shared [`ResponseBody`] shape. Used both for non-H3 origins and as the H3
/// fall-back path, so the two produce an identical result type.
async fn forward_via_hyper(
    shared: &Arc<Shared>,
    req: Request<ClientBody>,
) -> Result<hyper::Response<ResponseBody>, String> {
    shared
        .upstream
        .client
        .request(req)
        .await
        .map(|r| r.map(|b| b.map_err(|e| -> BoxError { e.into() }).boxed_unsync()))
        .map_err(|e| e.to_string())
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

/// Build the plaintext error reply shared by every proxy error path: status,
/// a `Content-Type` describing the message, and the message.
///
/// The `Content-Type` is not decoration. These responses carry a line of US-ASCII
/// text and used to carry no media type at all, which is exactly what
/// `content_type_present` reports -- RFC 9110 § 8.3 leaves such a
/// recipient to assume `application/octet-stream` or to sniff the bytes. A proxy
/// that lints for a missing Content-Type should not be answering with one.
pub(super) fn error_response(status: u16, body: String) -> ProxiedResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    ProxiedResponse {
        status,
        headers,
        body: boxed_full(Bytes::from(body)),
    }
}

/// Convert a [`ProxiedResponse`] into the hyper response the H1/H2 transport
/// hands back to the client. (The H3 transport drives the body itself and does
/// not come through here.)
pub(super) fn into_response(proxied: ProxiedResponse) -> hyper::Response<ResponseBody> {
    let mut resp_builder = hyper::Response::builder().status(proxied.status);
    for (name, value) in proxied.headers.iter() {
        resp_builder = resp_builder.header(name, value);
    }
    // The streaming body can't be cloned, so fall back to a fresh error
    // response if building fails (it shouldn't: status + filtered headers are
    // valid). The fallback's own build cannot fail the same way -- its status
    // and header are constants -- so the recursion is one level deep.
    resp_builder.body(proxied.body).unwrap_or_else(|e| {
        error!("failed to build client response: {}", e);
        into_response(error_response(502, "failed to build response".to_string()))
    })
}

/// Record an error transaction from inside [`exchange`] (build / upstream
/// failure), using whatever request-body prefix the tee captured before the
/// request was dropped.
async fn record_exchange_error(
    shared: &Arc<Shared>,
    facts: &RequestFacts,
    status: u16,
    duration_ms: u64,
    req_captured: Option<&CapturedBody>,
) {
    record_error_transaction(
        shared,
        facts,
        ErrorFacts {
            status,
            duration_ms,
            req_body: req_captured.map(|c| c.prefix.clone()),
            request_body_over_limit: req_captured.is_some_and(|c| c.truncated),
            ..Default::default()
        },
    )
    .await;
}

/// The response-side facts of a failed exchange: everything
/// [`record_error_transaction`] cannot read from the request facts.
#[derive(Default)]
pub(super) struct ErrorFacts {
    pub status: u16,
    pub duration_ms: u64,
    pub response_headers: Option<HeaderMap>,
    pub req_body: Option<Bytes>,
    pub request_body_over_limit: bool,
    pub response_body_over_limit: bool,
}

/// Build a minimal `HttpTransaction` (request + response status only) and route
/// it through the full pipeline (lint → state record → capture), so error
/// exchanges are linted and enter `TransactionHistory` like any other traffic.
/// Used on the error paths where the upstream exchange never completes
/// normally. Shared by both transports and the WebSocket handshake.
pub(super) async fn record_error_transaction(
    shared: &Arc<Shared>,
    facts: &RequestFacts,
    err: ErrorFacts,
) {
    let mut tx = crate::http_transaction::HttpTransaction::new(
        facts.client_id.clone(),
        facts.method.as_str().to_string(),
        facts.uri_str.clone(),
    );
    tx.request.headers = facts.headers.clone();
    tx.request.version = facts.version.clone();
    if let Some(b) = err.req_body {
        tx.request.body_length = Some(b.len() as u64);
        tx.request_body = Some(b);
    }
    tx.request_body_over_limit = err.request_body_over_limit;
    tx.response_body_over_limit = err.response_body_over_limit;
    tx.response = Some(crate::http_transaction::ResponseInfo {
        status: err.status,
        version: facts.version.clone(),
        headers: err.response_headers.unwrap_or_default(),
        body_length: None,
        trailers: None,
    });
    tx.timing = crate::http_transaction::TimingInfo {
        duration_ms: err.duration_ms,
    };
    tx.connection_id = Some(facts.connection_id);
    tx.sequence_number = Some(facts.sequence_number);
    // Lint, record to state, and capture — error exchanges are real traffic.
    shared.pipeline().commit(tx).await;
}
