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
use hyper::{HeaderMap, Request, Response, Uri, Version};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

use crate::config::Config;

use super::{BoxError, ClientBody, ResponseBody};

/// Upper bound on distinct authorities held in the negative cache; expired
/// entries are pruned before this is exceeded so a churn of one-off origins
/// can't grow the map without bound.
const NEGATIVE_CACHE_CAP: usize = 1024;

/// Same bound for the Alt-Svc discovery cache — a proxy that sees many distinct
/// origins advertising H3 must not accumulate mappings without limit.
const DISCOVERY_CACHE_CAP: usize = 1024;

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

/// Default freshness for a discovered Alt-Svc mapping when it carries no `ma`
/// (RFC 7838 §3.1 leaves the default to the client; 24h is the common choice,
/// matching the alt-svc rule's documented assumption).
const DEFAULT_ALT_SVC_MA_SECS: u64 = 24 * 60 * 60;

/// A discovered Alt-Svc mapping: the advertised H3 endpoints and when the
/// mapping stops being fresh (`ma`).
struct DiscoveryEntry {
    endpoints: Vec<(String, u16)>,
    expiry: Instant,
}

/// Where and how to open an H3 connection for an origin authority: the QUIC
/// endpoint to dial (the origin itself, or an Alt-Svc alternative) and the TLS
/// server name — always the **origin** authority host, so the endpoint's
/// certificate must validate *for the origin* (RFC 7838 §2.1 / RFC 9114 §3.3),
/// not merely for the alternative's own name.
pub(super) struct H3Route {
    dial_host: String,
    dial_port: u16,
    authority_host: String,
}

/// Shared HTTP/3 upstream client: one quinn client endpoint plus the set of
/// origin authorities eligible for H3 forwarding.
pub(super) struct H3UpstreamClient {
    endpoint: quinn::Endpoint,
    /// Origin authorities (`host:port`) the operator opted into always
    /// forwarding over H3, pre-seeding discovery.
    authorities: HashSet<String>,
    /// Origin authorities that must never use H3, overriding both the allowlist
    /// and Alt-Svc discovery.
    denylist: HashSet<String>,
    /// Whether an origin's Alt-Svc header may add an H3 route at runtime.
    trust_alt_svc: bool,
    /// Bound on the connect + handshake (and the response head).
    connect_timeout: Duration,
    /// Base backoff window for the negative cache.
    negative_ttl: Duration,
    /// Authorities whose H3 connect/handshake recently failed, suppressed from
    /// H3 attempts until their backoff window elapses.
    negative: Mutex<HashMap<String, NegEntry>>,
    /// Alt-Svc discovery cache: origin authority → advertised H3 endpoints.
    discovery: Mutex<HashMap<String, DiscoveryEntry>>,
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
        let denylist = cfg.general.h3_upstream_denylist.iter().cloned().collect();

        Ok(Some(Self {
            endpoint,
            authorities,
            denylist,
            trust_alt_svc: cfg.general.h3_upstream_trust_alt_svc,
            connect_timeout: Duration::from_millis(cfg.general.h3_upstream_connect_timeout_ms),
            negative_ttl: Duration::from_secs(cfg.general.h3_upstream_negative_ttl_seconds),
            negative: Mutex::new(HashMap::new()),
            discovery: Mutex::new(HashMap::new()),
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

    /// Resolve how to reach `authority` over HTTP/3, or `None` if it should not
    /// be attempted. The denylist wins over everything; otherwise the configured
    /// allowlist dials the origin directly, and a fresh Alt-Svc discovery dials
    /// the advertised endpoint. Either way the TLS name stays the origin host so
    /// the endpoint cert is validated for the origin (RFC 7838 §2.1).
    pub(super) fn route_for(&self, authority: &str) -> Option<H3Route> {
        if self.denylist.contains(authority) {
            return None;
        }
        let (host, port) = split_authority(authority)?;
        if self.authorities.contains(authority) {
            return Some(H3Route {
                dial_host: host.clone(),
                dial_port: port,
                authority_host: host,
            });
        }
        let (dial_host, dial_port) = self.discovered(authority)?;
        Some(H3Route {
            dial_host,
            dial_port,
            authority_host: host,
        })
    }

    /// Return a fresh discovered H3 endpoint for `authority`, if any.
    fn discovered(&self, authority: &str) -> Option<(String, u16)> {
        let map = self.discovery.lock().unwrap();
        let entry = map.get(authority)?;
        if entry.expiry <= Instant::now() {
            return None;
        }
        entry.endpoints.first().cloned()
    }

    /// Fold an origin's `Alt-Svc` response header(s) into the discovery cache:
    /// `clear` drops the mapping, an `h3` advertisement (re)populates it with the
    /// advertised endpoints and an `ma`-derived expiry. No-op when Alt-Svc trust
    /// is disabled. `origin_host` resolves the `":port"` (same-host) form.
    pub(super) fn record_alt_svc(&self, authority: &str, origin_host: &str, headers: &HeaderMap) {
        if !self.trust_alt_svc {
            return;
        }
        let origin_host = origin_host.trim_start_matches('[').trim_end_matches(']');
        for hv in headers.get_all("alt-svc").iter() {
            let Ok(s) = hv.to_str() else { continue };
            match parse_alt_svc(s, origin_host) {
                Some(AltSvc::Clear) => {
                    self.discovery.lock().unwrap().remove(authority);
                }
                Some(AltSvc::Advertise { endpoints, ma }) => {
                    let now = Instant::now();
                    let expiry = now
                        .checked_add(Duration::from_secs(ma))
                        .unwrap_or_else(|| now + Duration::from_secs(DEFAULT_ALT_SVC_MA_SECS));
                    let mut map = self.discovery.lock().unwrap();
                    // Bound the map: drop stale mappings before admitting a new
                    // authority (refreshing an existing key never grows it).
                    if map.len() >= DISCOVERY_CACHE_CAP && !map.contains_key(authority) {
                        map.retain(|_, e| e.expiry > now);
                    }
                    map.insert(authority.to_string(), DiscoveryEntry { endpoints, expiry });
                }
                None => {}
            }
        }
    }

    /// Forward `req` (already hop-by-hop stripped) to its origin over HTTP/3 and
    /// return a `hyper::Response` whose body streams the origin's response.
    /// Opens a fresh QUIC connection each call (P1: no pool). On failure the
    /// [`H3Failure`] tells the caller whether the request is safe to fall back
    /// to H1/H2.
    pub(super) async fn forward(
        &self,
        req: Request<ClientBody>,
        route: &H3Route,
    ) -> Result<Response<ResponseBody>, H3Failure> {
        // Build the https target + H3 head from the request URI *without
        // consuming* `req`, so it can be handed back for fall-back. The head
        // keeps the origin authority (`:authority`); only the dialed socket comes
        // from the route (an Alt-Svc alternative may differ from the origin).
        let https_uri = match force_https(req.uri()) {
            Ok(u) => u,
            Err(error) => return Err(pre_request(error, req)),
        };
        let head = match build_h3_head(&req, https_uri) {
            Ok(h) => h,
            Err(error) => return Err(pre_request(error, req)),
        };
        let addr = match lookup_endpoint(&route.dial_host, route.dial_port).await {
            Ok(a) => a,
            Err(error) => return Err(pre_request(error, req)),
        };

        // Connect + handshake, bounded by the configured timeout. Nothing has
        // reached the origin yet, so any failure here is safe to retry for any
        // method and triggers the negative cache. The TLS name is the *origin*
        // authority host, so a discovered endpoint's cert is validated for the
        // origin (RFC 7838 §2.1); a mismatch fails here and falls back.
        let connect = async {
            let conn = self.endpoint.connect(addr, &route.authority_host)?.await?;
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

/// Resolve `host:port` to a socket address for dialing the QUIC endpoint.
async fn lookup_endpoint(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("h3 upstream: could not resolve {host}:{port}"))
}

/// Split an `host[:port]` authority into its bracket-stripped host and port,
/// defaulting the port to 443 when absent (H3 is always TLS — this mirrors the
/// original `port_u16().unwrap_or(443)` so a no-port allowlist entry still
/// routes over H3). `Authority::host()` keeps the brackets on an IPv6 literal
/// (`[::1]`), which neither `lookup_host` nor a rustls `ServerName` accepts.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    let (host_part, port) = match authority.rfind(':') {
        // A ':' inside a bracketed IPv6 literal (before the closing ']') is not
        // a port separator, e.g. bare "[::1]".
        Some(i) if authority[i..].contains(']') => (authority, 443),
        Some(i) => (&authority[..i], authority[i + 1..].parse().ok()?),
        None => (authority, 443),
    };
    let host = host_part.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// The routing-relevant content of an `Alt-Svc` header.
enum AltSvc {
    /// `Alt-Svc: clear` — drop any cached mapping for the origin.
    Clear,
    /// One or more `h3=` advertisements plus the smallest `ma` seen.
    Advertise {
        endpoints: Vec<(String, u16)>,
        ma: u64,
    },
}

/// Parse an `Alt-Svc` header value for HTTP/3 routing. Reuses the alt-svc rules'
/// list/param splitting (`crate::helpers::headers`) and their acceptance
/// criteria — only the final `h3` token (draft `h3-NN` is rejected, as
/// `server_alt_svc_h3_advertisement_valid` flags). `origin_host` resolves the
/// `":port"` (same-host) advertisement form. Returns `None` when the header
/// carries no usable h3 route and no `clear`.
fn parse_alt_svc(header: &str, origin_host: &str) -> Option<AltSvc> {
    use crate::helpers::headers::{parse_list_header, split_semicolons_respecting_quotes};

    let mut endpoints = Vec::new();
    let mut ma = DEFAULT_ALT_SVC_MA_SECS;
    for entry in parse_list_header(header) {
        let mut parts = entry.splitn(2, ';');
        let proto_auth = parts.next().unwrap_or("").trim();
        let params = parts.next().unwrap_or("");

        if proto_auth.eq_ignore_ascii_case("clear") {
            return Some(AltSvc::Clear);
        }
        let Some(eq) = proto_auth.find('=') else {
            continue;
        };
        // Only the final `h3` ALPN token routes; draft `h3-NN` is not usable
        // (mirrors `server_alt_svc_h3_advertisement_valid`).
        if !proto_auth[..eq].trim().eq_ignore_ascii_case("h3") {
            continue;
        }
        let auth = proto_auth[eq + 1..].trim().trim_matches('"');
        let Some(endpoint) = parse_alt_authority(auth, origin_host) else {
            continue;
        };

        // An `ma=0` invalidates the advertisement; otherwise track the smallest
        // freshness across the h3 entries as the mapping's expiry.
        if let Some(entry_ma) = alt_svc_ma(&split_semicolons_respecting_quotes(params)) {
            if entry_ma == 0 {
                continue;
            }
            ma = ma.min(entry_ma);
        }
        endpoints.push(endpoint);
    }

    (!endpoints.is_empty()).then_some(AltSvc::Advertise { endpoints, ma })
}

/// Parse an Alt-Svc `alt-authority` (`[uri-host] ":" port`) into a dialable
/// `(host, port)`; an empty host means "same host as the origin".
fn parse_alt_authority(auth: &str, origin_host: &str) -> Option<(String, u16)> {
    let colon = auth.rfind(':')?;
    let port: u16 = auth[colon + 1..].parse().ok()?;
    let host = auth[..colon].trim_start_matches('[').trim_end_matches(']');
    let host = if host.is_empty() {
        origin_host.to_string()
    } else {
        host.to_string()
    };
    Some((host, port))
}

/// Extract the `ma` (max-age) parameter value from split Alt-Svc params, if any.
fn alt_svc_ma(params: &[&str]) -> Option<u64> {
    for param in params {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        if !key.eq_ignore_ascii_case("ma") {
            continue;
        }
        let raw = kv.next().unwrap_or("").trim();
        let val = raw
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(raw);
        return val.parse::<u64>().ok();
    }
    None
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

    fn client_with(mutate: impl FnOnce(&mut crate::config::GeneralConfig)) -> H3UpstreamClient {
        let mut cfg = Config::default();
        cfg.general.h3_upstream_enabled = true;
        mutate(&mut cfg.general);
        let roots = rustls::RootCertStore::empty();
        H3UpstreamClient::build(&cfg, &roots)
            .expect("build h3 client")
            .expect("h3 client is Some when enabled")
    }

    fn alt_svc_headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("alt-svc", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn parse_alt_svc_same_host_and_explicit_host() {
        match parse_alt_svc("h3=\":443\"; ma=3600", "example.com") {
            Some(AltSvc::Advertise { endpoints, ma }) => {
                assert_eq!(endpoints, vec![("example.com".to_string(), 443)]);
                assert_eq!(ma, 3600);
            }
            _ => panic!("expected an h3 advertisement"),
        }
        match parse_alt_svc("h3=\"alt.example.com:8443\"", "example.com") {
            Some(AltSvc::Advertise { endpoints, ma }) => {
                assert_eq!(endpoints, vec![("alt.example.com".to_string(), 8443)]);
                assert_eq!(ma, DEFAULT_ALT_SVC_MA_SECS, "absent ma defaults");
            }
            _ => panic!("expected advertise"),
        }
    }

    #[test]
    fn parse_alt_svc_rejects_draft_and_non_h3_and_clear() {
        assert!(
            parse_alt_svc("h3-29=\":443\"", "example.com").is_none(),
            "draft h3-NN is not a usable route"
        );
        assert!(
            parse_alt_svc("h2=\":443\"", "example.com").is_none(),
            "non-h3 protocols do not route H3"
        );
        assert!(matches!(
            parse_alt_svc("clear", "example.com"),
            Some(AltSvc::Clear)
        ));
        // ma=0 invalidates the h3 entry.
        assert!(parse_alt_svc("h3=\":443\"; ma=0", "example.com").is_none());
    }

    #[tokio::test]
    async fn discovery_populates_consults_and_clears() {
        let client = client_with(|_| {});
        let auth = "origin.example:443";

        assert!(client.route_for(auth).is_none(), "nothing discovered yet");

        client.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        let route = client.route_for(auth).expect("discovered route");
        assert_eq!(route.dial_host, "origin.example");
        assert_eq!(route.dial_port, 8443);
        assert_eq!(
            route.authority_host, "origin.example",
            "TLS name stays the origin authority (cert-for-origin)"
        );

        client.record_alt_svc(auth, "origin.example", &alt_svc_headers(&["clear"]));
        assert!(
            client.route_for(auth).is_none(),
            "Alt-Svc: clear drops the mapping"
        );
    }

    #[tokio::test]
    async fn discovery_honours_ma_expiry() {
        let client = client_with(|_| {});
        let auth = "origin.example:443";
        // A fresh mapping is consulted.
        client.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            client.route_for(auth).is_some(),
            "fresh mapping is consulted"
        );

        // Force the entry's expiry into the past: it must no longer be consulted.
        {
            let mut map = client.discovery.lock().unwrap();
            let entry = map.get_mut(auth).unwrap();
            entry.expiry = Instant::now() - Duration::from_secs(1);
        }
        assert!(
            client.route_for(auth).is_none(),
            "an expired mapping (ma elapsed) is not consulted"
        );
    }

    #[tokio::test]
    async fn discovery_ignored_when_trust_disabled() {
        let client = client_with(|g| g.h3_upstream_trust_alt_svc = false);
        let auth = "origin.example:443";
        client.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            client.route_for(auth).is_none(),
            "Alt-Svc discovery is off, so no route"
        );
    }

    #[tokio::test]
    async fn route_allowlist_and_denylist() {
        let client = client_with(|g| {
            g.h3_upstream_authorities = vec!["allow.example:443".to_string()];
            g.h3_upstream_denylist = vec!["deny.example:443".to_string()];
        });
        let route = client.route_for("allow.example:443").expect("allowlisted");
        assert_eq!(route.dial_host, "allow.example");
        assert_eq!(route.dial_port, 443);
        assert!(
            client.route_for("other.example:443").is_none(),
            "not allowlisted, not discovered"
        );

        // Denylist wins even over a discovered mapping.
        client.record_alt_svc(
            "deny.example:443",
            "deny.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            client.route_for("deny.example:443").is_none(),
            "denylist overrides discovery"
        );
    }

    #[tokio::test]
    async fn route_defaults_missing_port_to_443() {
        // A no-port allowlist entry still routes over H3 (H3 is always TLS), as
        // it did before Alt-Svc routing landed.
        let client = client_with(|g| {
            g.h3_upstream_authorities = vec!["example.com".to_string()];
        });
        let route = client
            .route_for("example.com")
            .expect("no-port entry routes");
        assert_eq!(route.dial_host, "example.com");
        assert_eq!(route.dial_port, 443);
    }

    #[test]
    fn split_authority_forms() {
        assert_eq!(
            split_authority("example.com:8443"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            split_authority("example.com"),
            Some(("example.com".to_string(), 443)),
            "absent port defaults to 443"
        );
        assert_eq!(split_authority("[::1]:443"), Some(("::1".to_string(), 443)));
        assert_eq!(
            split_authority("[::1]"),
            Some(("::1".to_string(), 443)),
            "bracketed IPv6 without a port defaults to 443, not a mis-split"
        );
    }
}
