// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP proxy server implementation with request forwarding and capture.

mod body;
mod connect;
mod exchange;
mod hop_by_hop;
mod http;
mod http3;
mod http3_body;
mod pipeline;
mod stream;
mod tee_body;
#[cfg(test)]
mod test_support;
mod upstream;
mod upstream_h3;
mod websocket;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{service::service_fn, Request, Response};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::ca::CertificateAuthority;
use crate::capture::CaptureWriter;
use crate::config::Config;

use self::http::handle_request;
use self::http3::{init_h3_endpoint, run_h3_accept_loop, H3Bind};

/// Body type returned to the client. Streaming upstream responses can error
/// mid-body (the inner `Incoming` is fallible), so unlike the request side this
/// carries a real error rather than `Infallible`. Unsync because `Incoming` is
/// not `Sync`; `serve_connection` only requires `Send`.
pub(super) type ResponseBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// Wrap fully-buffered bytes (proxy-generated responses: errors, the CA cert,
/// CONNECT acks) as a [`ResponseBody`]. `Full` is infallible, so the boxed
/// error never materializes.
pub(super) fn boxed_full(body: Bytes) -> ResponseBody {
    Full::new(body).map_err(|e| match e {}).boxed_unsync()
}

pub(super) type ServiceFuture =
    Pin<Box<dyn Future<Output = Result<Response<ResponseBody>, Infallible>> + Send>>;

/// Boxed error for the upstream request body — `Full<Bytes>` for buffered
/// bodies (WebSocket, H3) or a streaming `TeeBody` for H1/H2 requests.
pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Request body type sent to the upstream client. Unsync (like [`ResponseBody`])
/// so it can carry a streaming/teeing request body; the client only requires
/// `Send`.
pub(super) type ClientBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

pub(super) struct Shared {
    /// Outbound resources (forwarding client + shared TLS config), built once
    /// from a single trust-store load. See [`upstream::Upstream`].
    pub(super) upstream: upstream::Upstream,
    pub(super) captures: CaptureWriter,
    pub(super) cfg: Arc<Config>,
    pub(super) state: Arc<crate::state::StateStore>,
    pub(super) protocol_event_store: Arc<crate::protocol_event_store::ProtocolEventStore>,
    pub(super) ca: Option<Arc<CertificateAuthority>>,
    pub(super) quic_transport_params: Option<crate::protocol_event::QuicTransportParameters>,
    /// Enabled rule set precomputed once from `cfg` (immutable after startup),
    /// so per-transaction/-event dispatch skips disabled rules without a
    /// per-rule config lookup. Shared by both pipelines.
    pub(super) engine: Arc<crate::engine::PreparedEngine>,
    /// Connection bound, shared with the accept loops. The detached WebSocket
    /// relay holds a permit from this for its whole life — acquired before the
    /// upstream dial, refusing the upgrade with a 503 at capacity — so every
    /// live session is counted against `max_connections` and waited on by the
    /// shutdown drain barrier.
    pub(super) semaphore: Arc<Semaphore>,
    /// Graceful-shutdown signal. Handed to the detached WebSocket relay so it
    /// closes promptly on shutdown rather than only at the drain timeout.
    pub(super) shutdown: CancellationToken,
}

/// Where the accept loop's socket comes from.
///
/// The binary names an address and the proxy binds it. A caller that has
/// already bound the socket hands the listener over instead: choosing an
/// ephemeral port with `127.0.0.1:0`, reading the address back and dropping the
/// listener leaves a window in which anything else can take that port, and the
/// proxy then either fails to bind or — worse — the caller's traffic reaches
/// whoever won it. Handing over the listener closes the window, because the
/// port is never unowned.
///
/// All three entry points take `impl Into<ListenOn>`, so an address still
/// passes unchanged; a caller that wants the guarantee passes its `TcpListener`,
/// or a `(TcpListener, UdpSocket)` pair when HTTP/3 is configured too.
pub enum ListenOn {
    /// Bind this address when the accept loop starts, and — if HTTP/3 is
    /// configured — the address `general.h3_listen` names.
    Addr(SocketAddr),
    /// Accept on sockets the caller has already bound. `h3` decides only which
    /// socket the QUIC endpoint runs on; whether it runs at all is still
    /// `general.h3_listen`, and leaving `h3` `None` there binds that address as
    /// usual.
    Bound {
        tcp: std::net::TcpListener,
        h3: Option<std::net::UdpSocket>,
    },
}

impl From<SocketAddr> for ListenOn {
    fn from(addr: SocketAddr) -> Self {
        Self::Addr(addr)
    }
}

impl From<std::net::TcpListener> for ListenOn {
    fn from(tcp: std::net::TcpListener) -> Self {
        Self::Bound { tcp, h3: None }
    }
}

impl From<(std::net::TcpListener, std::net::UdpSocket)> for ListenOn {
    fn from((tcp, h3): (std::net::TcpListener, std::net::UdpSocket)) -> Self {
        Self::Bound { tcp, h3: Some(h3) }
    }
}

/// The TCP half of a [`ListenOn`], once the QUIC half has been taken off it.
/// Its own type rather than a `ListenOn` with `h3: None`, which would be a field
/// that means nothing at the one place it is read.
enum TcpSource {
    Addr(SocketAddr),
    Bound(std::net::TcpListener),
}

impl ListenOn {
    /// Split into the TCP half and the QUIC socket, if one was handed over. The
    /// QUIC endpoint is built well before the TCP accept loop, so the two halves
    /// are wanted at different points.
    fn split(self) -> (TcpSource, Option<std::net::UdpSocket>) {
        match self {
            Self::Addr(addr) => (TcpSource::Addr(addr), None),
            Self::Bound { tcp, h3 } => (TcpSource::Bound(tcp), h3),
        }
    }
}

impl TcpSource {
    /// Bind the address, or adopt the listener already bound to it.
    async fn into_listener(self) -> anyhow::Result<tokio::net::TcpListener> {
        Ok(match self {
            Self::Addr(addr) => tokio::net::TcpListener::bind(addr).await?,
            Self::Bound(tcp) => {
                tcp.set_nonblocking(true)?;
                tokio::net::TcpListener::from_std(tcp)?
            }
        })
    }
}

pub async fn run_proxy(
    listen: impl Into<ListenOn>,
    captures: CaptureWriter,
    cfg: Arc<Config>,
) -> anyhow::Result<()> {
    // Translate Ctrl-C into a cancellation the accept loop and handlers observe.
    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("ctrl-c received, shutting down");
                shutdown.cancel();
            }
        });
    }
    run_proxy_inner(listen.into(), captures, cfg, None, shutdown).await
}

/// Testable variant of `run_proxy` that accepts an optional `accept_limit`.
/// When `accept_limit` is `Some(n)`, the accept loop will accept `n` connections
/// and then return. Used by tests to deterministically bound accepts; the
/// shutdown sequence still runs (stop accepting, drain handlers, flush
/// captures) before returning.
pub async fn run_proxy_with_limit(
    listen: impl Into<ListenOn>,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    run_proxy_inner(
        listen.into(),
        captures,
        cfg,
        accept_limit,
        CancellationToken::new(),
    )
    .await
}

/// Variant that runs until `shutdown` is cancelled (or Ctrl-C is wired by the
/// caller). Lets shutdown integration tests drive graceful shutdown directly.
pub async fn run_proxy_with_shutdown(
    listen: impl Into<ListenOn>,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    run_proxy_inner(listen.into(), captures, cfg, None, shutdown).await
}

async fn run_proxy_inner(
    listen: ListenOn,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    accept_limit: Option<usize>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let (listen_tcp, listen_h3) = listen.split();

    // Load the platform trust store once; the forwarding client and the
    // WebSocket-upgrade path share it.
    let upstream = upstream::Upstream::new(&cfg)?;
    let ca = load_ca(&cfg).await?;

    let ttl = cfg.general.ttl_seconds;
    let state = Arc::new(crate::state::StateStore::new(ttl, cfg.general.max_history));
    let protocol_event_store = Arc::new(crate::protocol_event_store::ProtocolEventStore::new(
        ttl,
        cfg.general.max_protocol_event_history,
    ));

    seed_state_from_captures(&cfg, &state).await;

    // Connection bound and drain budget. Read before `cfg` moves into `Shared`.
    let max_connections = cfg.general.max_connections;
    let shutdown_timeout = Duration::from_secs(cfg.general.shutdown_timeout_seconds);
    let semaphore = Arc::new(Semaphore::new(max_connections));

    let cleanup_handle = spawn_expiry_sweep(state.clone(), protocol_event_store.clone(), &shutdown);

    // QUIC parameters are computed before `Shared` because they are stored on
    // it, to be emitted as protocol events when connections are established.
    let (h3_endpoint, quic_transport_params) = prepare_h3(&cfg, listen_h3, ca.as_ref())?;

    // Enabled rule set precomputed once; cfg is immutable from here on.
    let engine = Arc::new(crate::engine::PreparedEngine::new(&cfg)?);

    let shared = Arc::new(Shared {
        upstream,
        captures,
        cfg,
        state,
        protocol_event_store,
        ca,
        quic_transport_params,
        engine,
        semaphore: semaphore.clone(),
        shutdown: shutdown.clone(),
    });

    let pool_sweep_handle = spawn_h3_pool_sweep(&shared, &shutdown);

    // The H3 accept loop shares the connection semaphore with TCP, so
    // `max_connections` bounds both transports and the drain below waits for
    // live H3 connections too.
    let h3_handle = h3_endpoint.map(|endpoint| {
        let shared = shared.clone();
        let shutdown = shutdown.clone();
        let semaphore = semaphore.clone();
        tokio::spawn(async move { run_h3_accept_loop(endpoint, shared, shutdown, semaphore).await })
    });

    // A manual accept loop preserves the remote address, which hyper v1 gives
    // no other way to reach.
    let listener = listen_tcp.into_listener().await?;
    // Read the address back off the socket rather than echoing the request: with
    // `:0` the requested port is 0 and the bound one is what a client needs.
    //
    // Bound before it is logged: a tracing field expression is evaluated only
    // when the level is enabled, so inlining this call would skip both it and
    // its error propagation whenever INFO is off.
    let listen = listener.local_addr()?;
    info!(%listen, "listening");
    accept_until_shutdown(listener, &shared, &semaphore, &shutdown, accept_limit).await?;

    // Graceful shutdown: stop accepting (done), cancel handlers, then drain.
    shutdown.cancel();
    drain_connections(&semaphore, max_connections, shutdown_timeout).await;

    let _ = cleanup_handle.await;
    for handle in [h3_handle, pool_sweep_handle].into_iter().flatten() {
        let _ = handle.await;
    }

    // Flush, fsync, and join the capture writer last, after all handlers that
    // could write to it have drained, so no capture line is lost or truncated.
    if let Err(e) = shared.captures.shutdown().await {
        warn!(error = %e, "failed to shut down capture writer");
    }

    Ok(())
}

/// Load or generate the CA the TLS interception path signs with, when TLS is
/// enabled at all.
async fn load_ca(cfg: &Config) -> anyhow::Result<Option<Arc<CertificateAuthority>>> {
    if !cfg.tls.enabled {
        return Ok(None);
    }
    let cert_path = cfg.tls.ca_cert_path.as_deref().unwrap_or("ca.crt");
    let key_path = cfg.tls.ca_key_path.as_deref().unwrap_or("ca.key");
    Ok(Some(
        CertificateAuthority::load_or_generate(
            std::path::Path::new(cert_path),
            std::path::Path::new(key_path),
        )
        .await?,
    ))
}

/// Build the QUIC endpoint and its transport parameters, when HTTP/3 is
/// configured. Both are `None` together, and `h3_listen` without TLS is a
/// configuration error rather than a silent downgrade: the endpoint has no
/// certificate to present.
fn prepare_h3(
    cfg: &Config,
    listen_h3: Option<std::net::UdpSocket>,
    ca: Option<&Arc<CertificateAuthority>>,
) -> anyhow::Result<(
    Option<quinn::Endpoint>,
    Option<crate::protocol_event::QuicTransportParameters>,
)> {
    let Some(h3_listen) = cfg.general.h3_listen.as_ref() else {
        return Ok((None, None));
    };
    let ca = ca
        .ok_or_else(|| anyhow::anyhow!("h3_listen requires TLS to be enabled"))?
        .clone();
    let server_name = cfg
        .general
        .h3_server_name
        .clone()
        .unwrap_or_else(|| "localhost".to_string());
    let bind = match listen_h3 {
        Some(socket) => H3Bind::Bound(socket),
        None => H3Bind::Addr(h3_listen.parse()?),
    };
    let (endpoint, params) = init_h3_endpoint(bind, &server_name, &ca)?;
    Ok((Some(endpoint), Some(params)))
}

/// Spawn the periodic eviction of expired transactions and protocol events,
/// cancellable so shutdown can join it.
fn spawn_expiry_sweep(
    state: Arc<crate::state::StateStore>,
    protocol_events: Arc<crate::protocol_event_store::ProtocolEventStore>,
    shutdown: &CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    state.cleanup_expired();
                    protocol_events.cleanup_expired();
                }
                _ = shutdown.cancelled() => break,
            }
        }
    })
}

/// Spawn the periodic eviction of idle pooled H3 *upstream* connections. Only
/// spawned when the H3 upstream client exists.
fn spawn_h3_pool_sweep(
    shared: &Arc<Shared>,
    shutdown: &CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    shared.upstream.h3.as_ref()?;
    let shared = shared.clone();
    let shutdown = shutdown.clone();
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(h3) = shared.upstream.h3.as_ref() {
                        h3.sweep_idle();
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    }))
}

/// Accept connections until shutdown is cancelled, or until `accept_limit`
/// connections have been accepted (which is how the tests bound a run).
///
/// The loop is bounded by the connection semaphore: a permit is reserved
/// *before* accepting, so the count can never exceed `max_connections`, and
/// each accepted connection holds an owned permit for its lifetime — which is
/// what makes the semaphore double as the drain barrier.
async fn accept_until_shutdown(
    listener: tokio::net::TcpListener,
    shared: &Arc<Shared>,
    semaphore: &Arc<Semaphore>,
    shutdown: &CancellationToken,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    let server_builder = AutoConnBuilder::new(TokioExecutor::new());
    let mut remaining = accept_limit;

    while remaining != Some(0) {
        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            permit = semaphore.clone().acquire_owned() => permit?,
        };

        let (stream, remote_addr) = tokio::select! {
            _ = shutdown.cancelled() => {
                drop(permit);
                break;
            }
            accepted = listener.accept() => accepted?,
        };

        if let Some(n) = remaining.as_mut() {
            *n -= 1;
        }

        let shared = shared.clone();
        let builder = server_builder.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            // Released when this task ends; the drain waits on all permits.
            let _permit = permit;
            serve_connection(stream, remote_addr, shared, builder, shutdown).await;
        });
    }

    Ok(())
}

/// Wait until every connection task has released its permit — acquiring the
/// full set proves the count is back to zero — bounded by the timeout.
async fn drain_connections(
    semaphore: &Arc<Semaphore>,
    max_connections: usize,
    shutdown_timeout: Duration,
) {
    let drain = semaphore.acquire_many(max_connections.min(u32::MAX as usize) as u32);
    if timeout(shutdown_timeout, drain).await.is_err() {
        warn!(
            timeout_s = shutdown_timeout.as_secs(),
            "shutdown drain timed out; some connections did not finish"
        );
    }
}

/// Seed in-memory state from the captures file when `captures_seed` is enabled.
/// Load failures are logged but never fail startup. Extracted from
/// `run_proxy_inner` to keep it within the cognitive-complexity budget.
async fn seed_state_from_captures(cfg: &Config, state: &crate::state::StateStore) {
    if !cfg.general.captures_seed {
        return;
    }
    match crate::capture::load_captures(&cfg.general.captures).await {
        Ok(records) => {
            let count = records.len();
            for record in &records {
                state.seed_from_transaction(record);
            }
            info!(count, "seeded state from captures");
        }
        Err(e) => {
            // Log warning but don't fail startup
            tracing::warn!(error = %e, "failed to load captures for seeding");
        }
    }
}

/// Serve a single accepted TCP connection until it closes or `shutdown` fires.
///
/// Extracted from the accept loop so `run_proxy_inner` stays within the
/// cognitive-complexity budget: this owns the per-connection service wiring and
/// the run-vs-graceful-shutdown select.
async fn serve_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    shared: Arc<Shared>,
    builder: AutoConnBuilder<TokioExecutor>,
    shutdown: CancellationToken,
) {
    let conn_metadata = Arc::new(crate::connection::ConnectionMetadata::new(remote_addr));
    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        let conn_metadata = conn_metadata.clone();
        let fut: ServiceFuture = Box::pin(async move {
            handle_request(
                req,
                shared.clone(),
                conn_metadata.clone(),
                hyper::http::uri::Scheme::HTTP,
            )
            .await
        });
        fut
    });

    let io = TokioIo::new(stream);
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                error!(%e, "connection error");
            }
        }
        _ = shutdown.cancelled() => {
            // Finish in-flight requests but stop reading new ones.
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await {
                error!(%e, "connection error after graceful shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::make_shared_with_cfg;
    use super::*;
    use std::sync::Arc as StdArc;
    use tokio::fs;

    #[tokio::test]
    async fn run_proxy_bind_fails_when_port_taken() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // run_proxy should return an error since the port is already in use
        let res = run_proxy(addr, cw, shared.cfg.clone()).await;
        assert!(res.is_err());

        let _ = fs::remove_file(&tmp).await;
        drop(l);
        Ok(())
    }

    /// The converse of the test above, and the reason [`ListenOn`] exists: a
    /// port that is already taken is exactly what a caller handing over its own
    /// listener cannot hit. The same port, bound by us, is fatal by address and
    /// fine by listener — so this pins the guarantee rather than the plumbing.
    #[tokio::test]
    async fn run_proxy_accepts_a_listener_on_a_port_it_could_not_have_bound() -> anyhow::Result<()>
    {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;
        let (_shared2, tmp2, cw2) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // By address, while we hold the port: the bind fails.
        assert!(run_proxy(addr, cw, shared.cfg.clone()).await.is_err());

        // By listener — the same port, never released — the accept loop starts
        // and stops only because it is told to accept nothing.
        run_proxy_with_limit(l, cw2, shared.cfg.clone(), Some(0)).await?;

        let _ = fs::remove_file(&tmp).await;
        let _ = fs::remove_file(&tmp2).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_capture_seed_load_error_logs_and_returns_error() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port so run_proxy will fail after startup
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        // Create a path that is a directory so load_captures will error when attempting to open it
        let mut temp = crate::temp_files::TempFiles::new();
        let dir = temp.dir("lint_proxy_seed_dir");
        tokio::fs::create_dir(&dir).await?;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.general.captures_seed = true;
        cfg_inner.general.captures = dir.to_string_lossy().to_string();
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None, &mut temp).await?;

        // run_proxy should still return an error due to port being taken, but during
        // startup it should attempt to seed captures and hit the Err branch.
        let res = run_proxy(addr, cw, shared.cfg.clone()).await;
        assert!(res.is_err());

        // Cleanup
        let _ = fs::remove_file(&tmp).await;
        tokio::fs::remove_dir(&dir).await?;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_starts_and_can_be_aborted() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, _tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, cw, shared.cfg.clone()).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        task.abort();
        let _ = task.await;

        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_one_connection_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // Pick a free port and keep the listener: dropping it here would leave
        // the port unowned until the spawned proxy rebinds it, and the tests in
        // this binary run concurrently.
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // spawn the proxy with accept_limit = 1
        let cw_clone = cw.clone();
        let cfg_clone = shared.cfg.clone();
        let task =
            tokio::spawn(
                async move { run_proxy_with_limit(l, cw_clone, cfg_clone, Some(1)).await },
            );

        // Wait until we can connect (server startup may be slightly delayed)
        // Keep the stream open until the server task completes to avoid races where
        // the connection is reset before the server has a chance to accept it.
        let mut connected = false;
        let mut stream_opt: Option<TcpStream> = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    connected = true;
                    stream_opt = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        assert!(connected, "failed to connect to proxy");

        // task should finish shortly after the single accept
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
        assert!(res.is_ok());
        // Drop the stream now that the proxy has accepted it
        drop(stream_opt);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_shutdown_drains_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        let shutdown = CancellationToken::new();
        let cfg_clone = shared.cfg.clone();
        let cw_clone = cw.clone();
        let shutdown_for_task = shutdown.clone();
        let task = tokio::spawn(async move {
            run_proxy_with_shutdown(l, cw_clone, cfg_clone, shutdown_for_task).await
        });

        // Connect so a handler is live and holding a permit, then let the proxy
        // accept it before we ask it to shut down.
        let mut stream_opt: Option<TcpStream> = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    stream_opt = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        assert!(stream_opt.is_some(), "failed to connect to proxy");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancellation should stop accepting, drain the live connection via
        // graceful shutdown, flush captures, and return Ok within the timeout.
        shutdown.cancel();
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
        assert!(res.is_ok());
        drop(stream_opt);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_zero_and_returns_immediately() -> anyhow::Result<()> {
        // pick a free port, and keep the listener rather than racing to rebind it
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (_shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // accept_limit = 0 should return quickly
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_proxy_with_limit(l, cw, _shared.cfg.clone(), Some(0)),
        )
        .await
        .expect("run_proxy_with_limit did not return within timeout")?;

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_two_connections_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // pick a free port, and keep the listener rather than racing to rebind it
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        let task =
            tokio::spawn(
                async move { run_proxy_with_limit(l, cw, shared.cfg.clone(), Some(2)).await },
            );

        // make two connections and keep them open until the server finishes
        let mut streams: Vec<TcpStream> = Vec::new();
        for _ in 0..2 {
            let mut connected = false;
            for _ in 0..100 {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        connected = true;
                        streams.push(s);
                        break;
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
            }
            assert!(connected, "failed to connect to proxy");
        }

        // task should finish after two accepts
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
        assert!(res.is_ok());
        // Drop the streams now that the proxy has accepted them
        drop(streams);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_capture_seed_load_success() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port so run_proxy will fail after startup
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        // Create a temporary captures JSONL with a single valid transaction
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp_capture = temp.path("lint_proxy_seed_ok", "jsonl");
        let pcap = tmp_capture
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Write a minimal transaction record
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.uri = "http://example/seed".to_string();
        let line = serde_json::to_string(&tx)? + "\n";
        tokio::fs::write(&tmp_capture, line).await?;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.general.captures_seed = true;
        cfg_inner.general.captures = pcap.clone();
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None, &mut temp).await?;

        // run_proxy should attempt to load captures and then fail on bind
        let res = run_proxy(addr, cw, shared.cfg.clone()).await;
        assert!(res.is_err());

        // Cleanup
        let _ = fs::remove_file(&tmp).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_tls_enabled_starts_and_can_be_aborted() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        // Use temp paths for CA files
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca_run", "crt");
        let key_path = temp.path("test_ca_run", "key");
        cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
        cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

        let cfg = StdArc::new(cfg);
        let (shared, _tmp, _cw) = make_shared_with_cfg(cfg.clone(), None, &mut temp).await?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, _cw, shared.cfg.clone()).await;
        });

        // Wait up to 2s for the CA files to be created by startup
        let start = std::time::Instant::now();
        while !(cert_path.exists() && key_path.exists()) {
            if start.elapsed() > std::time::Duration::from_secs(2) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        task.abort();
        let _ = task.await;

        // Ensure CA files were created by startup
        assert!(cert_path.exists());
        assert!(key_path.exists());

        Ok(())
    }
}
