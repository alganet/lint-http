// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The HTTP/3 (QUIC) *upstream* leg: forwarding a proxied request to an origin
//! over HTTP/3 instead of the hyper H1/H2 client.
//!
//! This is the outbound mirror of the client-facing H3 server in
//! [`super::http3`]. A single shared quinn client [`Endpoint`] (one UDP bind,
//! ALPN `h3`, the same native roots as the H1/H2 path) opens a fresh QUIC
//! connection per request — no pool yet — sends the request with the
//! hop-by-hop-stripped header section [`super::exchange`] already built, and
//! adapts the h3 response stream back into a [`ResponseBody`] so the shared
//! tee/commit machinery downstream is reused unchanged.
//!
//! # Field discipline (RFC 9114 §4.2)
//! An intermediary transforming a message to HTTP/3 MUST remove
//! connection-specific fields (Connection, Keep-Alive, Upgrade,
//! Transfer-Encoding, Proxy-*); a field section that carries one is *malformed*.
//! This path does not build its own header map — it forwards the request
//! [`super::exchange::build_upstream_request`] already stripped via the shared
//! hop-by-hop set (which covers exactly those fields), so the H3 request section
//! is well-formed by construction. Pseudo-headers (`:method`/`:scheme`/
//! `:path`/`:authority`) are derived by the h3 crate from the request's method
//! and absolute URI; the URI's scheme is forced to `https` here because there is
//! no plaintext HTTP/3.

use std::collections::{HashMap, HashSet};
use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::quic::RecvStream;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::http::uri::{PathAndQuery, Scheme};
use hyper::{Request, Response, Uri, Version};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

use crate::config::Config;

use super::{BoxError, ClientBody, ResponseBody};

/// Upper bound on distinct authorities held in the negative cache; expired
/// entries are pruned before this is exceeded so a churn of one-off origins
/// can't grow the map without bound.
const NEGATIVE_CACHE_CAP: usize = 1024;

/// Why an HTTP/3 upstream attempt failed, carrying enough context for the
/// caller to decide whether a fall-back to H1/H2 is safe (RFC 9110 §9.2.2).
pub(super) enum H3Failure {
    /// The failure left the request replayable — either nothing reached the
    /// origin (`pre_request`) or only the header section did with the body
    /// still intact. `request` is the original, un-consumed request. A
    /// `pre_request` failure is safe to fall back for **any** method and marks
    /// the origin in the negative cache; a header-sent failure is safe only for
    /// an idempotent method.
    Retryable {
        error: anyhow::Error,
        /// Boxed to keep this variant near the size of `Consumed` — a bare
        /// `Request<ClientBody>` would make the whole `H3Failure` large.
        request: Box<Request<ClientBody>>,
        pre_request: bool,
    },
    /// The request body was already in flight; the streaming body cannot be
    /// replayed, so the caller must not retry (whatever the method).
    Consumed { error: anyhow::Error },
}

/// One negative-cache entry: the origin is not attempted over H3 until `until`,
/// and `failures` drives the exponential backoff of that window.
struct NegEntry {
    until: Instant,
    failures: u32,
}

/// Shared HTTP/3 upstream client: one quinn client endpoint plus the set of
/// origin authorities eligible for H3 forwarding.
pub(super) struct H3UpstreamClient {
    endpoint: quinn::Endpoint,
    /// Origin authorities (`host:port`) the operator opted into forwarding over
    /// H3. Until Alt-Svc discovery lands this allowlist is the sole capability
    /// signal.
    authorities: HashSet<String>,
    /// Bound on the connect + handshake (and the response head).
    connect_timeout: Duration,
    /// Base backoff window for the negative cache.
    negative_ttl: Duration,
    /// Authorities whose H3 connect/handshake recently failed, suppressed from
    /// H3 attempts until their backoff window elapses.
    negative: Mutex<HashMap<String, NegEntry>>,
}

impl H3UpstreamClient {
    /// Build the client when `h3_upstream_enabled`, else return `None`. Uses the
    /// caller's native `roots` (so the trust store loads once) augmented with any
    /// `h3_upstream_extra_ca_certs` private CAs, and binds a single UDP endpoint.
    pub(super) fn build(
        cfg: &Config,
        roots: &rustls::RootCertStore,
    ) -> anyhow::Result<Option<Self>> {
        if !cfg.general.h3_upstream_enabled {
            return Ok(None);
        }

        // Clone the shared native roots and layer any configured private CAs on
        // top; rustls freezes the root set into the verifier at build time.
        let mut roots = roots.clone();
        for path in &cfg.general.h3_upstream_extra_ca_certs {
            let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(path)
                .map_err(|e| anyhow::anyhow!("h3_upstream_extra_ca_certs {path}: {e}"))?
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("h3_upstream_extra_ca_certs {path}: {e}"))?;
            for cert in certs {
                roots.add(cert).ok();
            }
        }

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("h3 upstream QUIC client config: {e}"))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        // Bound idle QUIC connections (P1 opens one per request; P4 pools them)
        // so a stranded connection winds down instead of lingering.
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s idle timeout fits"),
        ));
        client_config.transport_config(Arc::new(transport));

        let bind: SocketAddr = cfg
            .general
            .h3_upstream_bind
            .as_deref()
            .unwrap_or("0.0.0.0:0")
            .parse()
            .map_err(|e| anyhow::anyhow!("h3_upstream_bind: {e}"))?;
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config);

        let authorities = cfg
            .general
            .h3_upstream_authorities
            .iter()
            .cloned()
            .collect();

        Ok(Some(Self {
            endpoint,
            authorities,
            connect_timeout: Duration::from_millis(cfg.general.h3_upstream_connect_timeout_ms),
            negative_ttl: Duration::from_secs(cfg.general.h3_upstream_negative_ttl_seconds),
            negative: Mutex::new(HashMap::new()),
        }))
    }

    /// Whether `authority` is currently suppressed from H3 attempts by a live
    /// negative-cache backoff window.
    pub(super) fn is_suppressed(&self, authority: &str) -> bool {
        let map = self.negative.lock().unwrap();
        map.get(authority).is_some_and(|e| e.until > Instant::now())
    }

    /// Record a connect/handshake failure for `authority`, extending its
    /// backoff window (doubling per consecutive failure, capped).
    pub(super) fn record_failure(&self, authority: &str) {
        let now = Instant::now();
        let mut map = self.negative.lock().unwrap();
        if map.len() >= NEGATIVE_CACHE_CAP {
            map.retain(|_, e| e.until > now);
        }
        let entry = map.entry(authority.to_string()).or_insert(NegEntry {
            until: now,
            failures: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        // ttl * 2^(failures-1), shift capped at 6 (×64) to bound the window.
        // `checked_add` guards against an absurdly large configured ttl whose
        // saturated Duration would overflow `Instant` and panic this request task.
        let shift = (entry.failures - 1).min(6);
        let backoff = self.negative_ttl.saturating_mul(1u32 << shift);
        entry.until = now
            .checked_add(backoff)
            .unwrap_or_else(|| now + Duration::from_secs(24 * 60 * 60));
    }

    /// Clear any negative-cache entry for `authority` after a successful H3
    /// exchange, so a recovered origin resumes H3 immediately.
    pub(super) fn record_success(&self, authority: &str) {
        self.negative.lock().unwrap().remove(authority);
    }

    /// Whether requests to `authority` should be forwarded over HTTP/3.
    pub(super) fn handles(&self, authority: &str) -> bool {
        self.authorities.contains(authority)
    }

    /// Forward `req` (already hop-by-hop stripped) to its origin over HTTP/3 and
    /// return a `hyper::Response` whose body streams the origin's response.
    /// Opens a fresh QUIC connection each call (P1: no pool). On failure the
    /// [`H3Failure`] tells the caller whether the request is safe to fall back
    /// to H1/H2.
    pub(super) async fn forward(
        &self,
        req: Request<ClientBody>,
    ) -> Result<Response<ResponseBody>, H3Failure> {
        // Resolve the origin address / TLS name / https target from the request
        // URI *without consuming* `req`, so it can be handed back for fall-back.
        let (addr, host, https_uri) = match resolve_target(req.uri()).await {
            Ok(t) => t,
            Err(error) => return Err(pre_request(error, req)),
        };
        let head = match build_h3_head(&req, https_uri) {
            Ok(h) => h,
            Err(error) => return Err(pre_request(error, req)),
        };

        // Connect + handshake, bounded by the configured timeout. Nothing has
        // reached the origin yet, so any failure here is safe to retry for any
        // method and triggers the negative cache.
        let connect = async {
            let conn = self.endpoint.connect(addr, &host)?.await?;
            let pair = h3::client::new(h3_quinn::Connection::new(conn)).await?;
            Ok::<_, anyhow::Error>(pair)
        };
        let (mut driver, mut send_request) =
            match tokio::time::timeout(self.connect_timeout, connect).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(error)) => return Err(pre_request(error, req)),
                Err(_) => {
                    return Err(pre_request(
                        anyhow::anyhow!("h3 upstream connect timed out"),
                        req,
                    ))
                }
            };
        // Drive the connection in the background so request/response frames make
        // progress; aborted when the response body is dropped (see `ConnGuard`).
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // Open the request stream and send the header section. The origin may
        // have seen the header bytes, but the body is still intact, so fall-back
        // is safe only for an idempotent method (`pre_request = false`).
        let mut stream = match send_request.send_request(head).await {
            Ok(s) => s,
            Err(e) => {
                driver.abort();
                return Err(H3Failure::Retryable {
                    error: anyhow::anyhow!("h3 upstream send_request: {e}"),
                    request: Box::new(req),
                    pre_request: false,
                });
            }
        };

        // From here the request body streams to the origin and can no longer be
        // replayed, so any failure is non-retryable. Mirror the response side of
        // the client-facing handler: data frames forward as QUIC DATA, a trailing
        // trailers frame as an H3 trailers section.
        let (_, body) = req.into_parts();
        let send_body = async {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| anyhow::anyhow!("h3 upstream request body: {e}"))?;
                match frame.into_data() {
                    Ok(data) => stream.send_data(data).await?,
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            stream.send_trailers(trailers).await?;
                        }
                    }
                }
            }
            stream.finish().await?;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(error) = send_body.await {
            driver.abort();
            return Err(H3Failure::Consumed { error });
        }

        let resp_head =
            match tokio::time::timeout(self.connect_timeout, stream.recv_response()).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    driver.abort();
                    return Err(H3Failure::Consumed {
                        error: anyhow::anyhow!("h3 upstream recv_response: {e}"),
                    });
                }
                Err(_) => {
                    driver.abort();
                    return Err(H3Failure::Consumed {
                        error: anyhow::anyhow!("h3 upstream response timed out"),
                    });
                }
            };
        let (send_half, recv_half) = stream.split();

        // Record the origin leg's version as HTTP/3 (see the exchange core, which
        // reads `resp.version()` into `tx.response.version`).
        let mut builder = Response::builder()
            .status(resp_head.status())
            .version(Version::HTTP_3);
        for (name, value) in resp_head.headers() {
            builder = builder.header(name, value);
        }

        let guard = ConnGuard {
            _send_request: Box::new(send_request),
            _send_half: Box::new(send_half),
            driver,
        };
        let resp_body = H3ResponseBody {
            recv: recv_half,
            state: RespState::Data,
            _guard: guard,
        }
        .boxed_unsync();

        builder
            .body(resp_body)
            .map_err(|e| H3Failure::Consumed { error: e.into() })
    }
}

/// A pre-request failure: nothing reached the origin, so the request is
/// replayable for any method and the origin should be negative-cached.
fn pre_request(error: anyhow::Error, request: Request<ClientBody>) -> H3Failure {
    H3Failure::Retryable {
        error,
        request: Box::new(request),
        pre_request: true,
    }
}

/// Resolve the origin socket address, TLS server name, and https target URI
/// from a request URI, without consuming anything.
async fn resolve_target(uri: &Uri) -> anyhow::Result<(SocketAddr, String, Uri)> {
    let https_uri = force_https(uri)?;
    let authority = https_uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("h3 upstream: request URI has no authority"))?;
    // `Authority::host()` keeps the brackets on an IPv6 literal (`[::1]`), which
    // neither `lookup_host` nor a rustls `ServerName` accepts — strip them so
    // both the DNS/socket lookup and the TLS name are well-formed.
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = authority.port_u16().unwrap_or(443);
    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("h3 upstream: could not resolve {authority}"))?;
    Ok((addr, host, https_uri))
}

/// Build the HTTP/3 request head (method, https target, headers) from the
/// original request without consuming it, so a fall-back can reuse `req`.
fn build_h3_head(req: &Request<ClientBody>, https_uri: Uri) -> anyhow::Result<Request<()>> {
    let mut builder = Request::builder()
        .method(req.method().clone())
        .uri(https_uri)
        .version(req.version());
    for (name, value) in req.headers() {
        builder = builder.header(name, value);
    }
    Ok(builder.body(())?)
}

/// Rebuild `uri` with an `https` scheme (and a `/` path if none), so the H3
/// request carries a valid `:scheme`/`:path` even when the client reached the
/// proxy with an `http://` origin-form target.
fn force_https(uri: &Uri) -> anyhow::Result<Uri> {
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(Scheme::HTTPS);
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(PathAndQuery::from_static("/"));
    }
    Ok(Uri::from_parts(parts)?)
}

/// Keeps the QUIC connection alive for as long as the response body streams.
///
/// Dropping the last `SendRequest` triggers a client-initiated connection close
/// in the h3 crate, and the connection only advances while its driver task runs;
/// so both are held here until the body is fully read (or dropped), at which
/// point the driver is aborted and the connection winds down.
struct ConnGuard {
    _send_request: Box<dyn Send>,
    _send_half: Box<dyn Send>,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Whether the next poll reads response data, then trailers, then ends — the
/// receive-side mirror of [`super::http3_body`]'s request-body adapter.
enum RespState {
    Data,
    Trailers,
    Done,
}

/// Streams the origin's HTTP/3 response body out of the recv half of the client
/// request stream, yielding a trailers frame after the data if the origin sent
/// any. Owns a [`ConnGuard`] so the connection outlives the stream.
struct H3ResponseBody<S> {
    recv: h3::client::RequestStream<S, Bytes>,
    state: RespState,
    _guard: ConnGuard,
}

impl<S> Body for H3ResponseBody<S>
where
    S: RecvStream,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // `RequestStream` is `Unpin`, so poll the recv half without structural
        // pinning (the same pattern the request-body adapter uses).
        let this = self.get_mut();
        loop {
            match this.state {
                RespState::Data => match this.recv.poll_recv_data(cx) {
                    Poll::Ready(Ok(Some(mut buf))) => {
                        let bytes = buf.copy_to_bytes(buf.remaining());
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Poll::Ready(Ok(None)) => this.state = RespState::Trailers,
                    Poll::Ready(Err(e)) => {
                        this.state = RespState::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RespState::Trailers => match this.recv.poll_recv_trailers(cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        this.state = RespState::Done;
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = RespState::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(e)) => {
                        this.state = RespState::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RespState::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client(negative_ttl_seconds: u64) -> H3UpstreamClient {
        let mut cfg = Config::default();
        cfg.general.h3_upstream_enabled = true;
        cfg.general.h3_upstream_negative_ttl_seconds = negative_ttl_seconds;
        // An empty root store is fine: these tests never open a connection, they
        // only exercise the in-memory negative cache.
        let roots = rustls::RootCertStore::empty();
        H3UpstreamClient::build(&cfg, &roots)
            .expect("build h3 client")
            .expect("h3 client is Some when enabled")
    }

    #[tokio::test]
    async fn negative_cache_suppresses_then_clears_on_success() {
        let client = test_client(30);
        let auth = "origin.example:443";

        assert!(
            !client.is_suppressed(auth),
            "fresh authority is not suppressed"
        );

        client.record_failure(auth);
        assert!(
            client.is_suppressed(auth),
            "a connect failure suppresses H3 for the backoff window"
        );

        // A second failure keeps it suppressed (window doubles).
        client.record_failure(auth);
        assert!(client.is_suppressed(auth));

        client.record_success(auth);
        assert!(
            !client.is_suppressed(auth),
            "a success clears the negative-cache entry"
        );
    }

    #[tokio::test]
    async fn negative_cache_window_expires() {
        // A zero-second base TTL means the window is already elapsed on insert,
        // so the authority is not suppressed.
        let client = test_client(0);
        let auth = "origin.example:443";
        client.record_failure(auth);
        assert!(
            !client.is_suppressed(auth),
            "an elapsed window no longer suppresses"
        );
    }

    #[tokio::test]
    async fn negative_cache_only_covers_the_failing_authority() {
        let client = test_client(30);
        client.record_failure("a.example:443");
        assert!(client.is_suppressed("a.example:443"));
        assert!(
            !client.is_suppressed("b.example:443"),
            "suppression is per authority"
        );
    }
}
