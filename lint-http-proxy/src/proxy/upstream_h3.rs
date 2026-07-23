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

use std::collections::HashSet;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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

/// Shared HTTP/3 upstream client: one quinn client endpoint plus the set of
/// origin authorities eligible for H3 forwarding.
pub(super) struct H3UpstreamClient {
    endpoint: quinn::Endpoint,
    /// Origin authorities (`host:port`) the operator opted into forwarding over
    /// H3. Until Alt-Svc discovery lands this allowlist is the sole capability
    /// signal.
    authorities: HashSet<String>,
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
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));

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
        }))
    }

    /// Whether requests to `authority` should be forwarded over HTTP/3.
    pub(super) fn handles(&self, authority: &str) -> bool {
        self.authorities.contains(authority)
    }

    /// Forward `req` (already hop-by-hop stripped) to its origin over HTTP/3 and
    /// return a `hyper::Response` whose body streams the origin's response.
    /// Opens a fresh QUIC connection each call (P1: no pool).
    pub(super) async fn forward(
        &self,
        req: Request<ClientBody>,
    ) -> anyhow::Result<Response<ResponseBody>> {
        let (mut parts, body) = req.into_parts();

        // HTTP/3 is always over TLS: force the origin request's :scheme to https.
        let uri = force_https(&parts.uri)?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("h3 upstream: request URI has no authority"))?
            .clone();
        // `Authority::host()` keeps the brackets on an IPv6 literal (`[::1]`),
        // which neither `lookup_host` nor a rustls `ServerName` accepts — strip
        // them so both the DNS/socket lookup and the TLS name are well-formed.
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
        parts.uri = uri;
        let head = Request::from_parts(parts, ());

        let conn = self.endpoint.connect(addr, &host)?.await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(conn)).await?;
        // Drive the connection in the background so request/response frames make
        // progress; aborted when the response body is dropped (see `ConnGuard`).
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut stream = send_request.send_request(head).await?;

        // Stream the request body to the origin, mirroring the response side of
        // the client-facing handler: data frames forward as QUIC DATA, a trailing
        // trailers frame as an H3 trailers section.
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

        let resp_head = stream.recv_response().await?;
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

        Ok(builder.body(resp_body)?)
    }
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
