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
use self::http3::{init_h3_endpoint, run_h3_accept_loop};

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
    /// relay acquires a permit from this so live sessions are counted against
    /// `max_connections` and waited on by the shutdown drain barrier.
    pub(super) semaphore: Arc<Semaphore>,
    /// Graceful-shutdown signal. Handed to the detached WebSocket relay so it
    /// closes promptly on shutdown rather than only at the drain timeout.
    pub(super) shutdown: CancellationToken,
}

pub async fn run_proxy(
    listen: SocketAddr,
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
    run_proxy_inner(listen, captures, cfg, None, shutdown).await
}

/// Testable variant of `run_proxy` that accepts an optional `accept_limit`.
/// When `accept_limit` is `Some(n)`, the accept loop will accept `n` connections
/// and then return. Used by tests to deterministically bound accepts; the
/// shutdown sequence still runs (stop accepting, drain handlers, flush
/// captures) before returning.
pub async fn run_proxy_with_limit(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    run_proxy_inner(
        listen,
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
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    run_proxy_inner(listen, captures, cfg, None, shutdown).await
}

async fn run_proxy_inner(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    accept_limit: Option<usize>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // Load the platform trust store once; the forwarding client and the
    // WebSocket-upgrade path share it.
    let upstream = upstream::Upstream::new()?;

    let ca = if cfg.tls.enabled {
        let cert_path = cfg.tls.ca_cert_path.as_deref().unwrap_or("ca.crt");
        let key_path = cfg.tls.ca_key_path.as_deref().unwrap_or("ca.key");
        Some(
            CertificateAuthority::load_or_generate(
                std::path::Path::new(cert_path),
                std::path::Path::new(key_path),
            )
            .await?,
        )
    } else {
        None
    };

    let ttl = cfg.general.ttl_seconds;
    let max_history = cfg.general.max_history;
    let state = Arc::new(crate::state::StateStore::new(ttl, max_history));
    let protocol_event_store = Arc::new(crate::protocol_event_store::ProtocolEventStore::new(
        ttl,
        cfg.general.max_protocol_event_history,
    ));

    // Seed state from captures file if enabled
    seed_state_from_captures(&cfg, &state).await;

    // Connection bound and drain budget. Read before `cfg` moves into `Shared`.
    let max_connections = cfg.general.max_connections;
    let shutdown_timeout = Duration::from_secs(cfg.general.shutdown_timeout_seconds);
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Spawn background cleanup task, cancellable so shutdown can join it.
    let state_cleanup = state.clone();
    let pe_store_cleanup = protocol_event_store.clone();
    let cleanup_shutdown = shutdown.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    state_cleanup.cleanup_expired();
                    pe_store_cleanup.cleanup_expired();
                }
                _ = cleanup_shutdown.cancelled() => break,
            }
        }
    });

    // Pre-compute QUIC transport parameters and endpoint if HTTP/3 is
    // configured, so the values can be stored on `Shared` and emitted as
    // protocol events when connections are established.
    let (h3_endpoint, quic_transport_params) = if let Some(ref h3_listen) = cfg.general.h3_listen {
        let h3_addr: SocketAddr = h3_listen.parse()?;
        let h3_ca = ca
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("h3_listen requires TLS to be enabled"))?
            .clone();
        let server_name = cfg
            .general
            .h3_server_name
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let (endpoint, params) = init_h3_endpoint(h3_addr, &server_name, &h3_ca)?;
        (Some(endpoint), Some(params))
    } else {
        (None, None)
    };

    // Precompute the enabled rule set once; cfg is immutable from here on.
    let engine = Arc::new(crate::engine::PreparedEngine::new(&cfg));

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

    // Start HTTP/3 (QUIC) accept loop if an endpoint was created. It shares the
    // same connection semaphore as TCP, so `max_connections` bounds both
    // transports and the drain barrier below waits for live H3 connections too.
    let h3_handle = h3_endpoint.map(|endpoint| {
        let shared_h3 = shared.clone();
        let shutdown_h3 = shutdown.clone();
        let semaphore_h3 = semaphore.clone();
        tokio::spawn(async move {
            run_h3_accept_loop(endpoint, shared_h3, shutdown_h3, semaphore_h3).await;
        })
    });

    // Use a manual TcpListener accept loop to preserve the remote address and
    // avoid relying on the removed `make_service_fn` helper in hyper v1.
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "listening");

    let executor = TokioExecutor::new();
    let server_builder = AutoConnBuilder::new(executor);

    // Accept loop, bounded by the connection semaphore and interruptible by
    // shutdown. Each accepted connection holds an owned permit for its lifetime,
    // so the semaphore doubles as the drain barrier below.
    let mut remaining = accept_limit;
    loop {
        if let Some(0) = remaining {
            break;
        }

        // Reserve a slot first, so we never accept beyond `max_connections`.
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
        let builder_clone = server_builder.clone();
        let shutdown_conn = shutdown.clone();
        tokio::spawn(async move {
            // Released when this task ends; the drain waits on all permits.
            let _permit = permit;
            serve_connection(stream, remote_addr, shared, builder_clone, shutdown_conn).await;
        });
    }

    // Graceful shutdown: stop accepting (done), cancel handlers, then drain.
    shutdown.cancel();

    // Wait until every connection task has released its permit (acquiring the
    // full set proves the count is back to zero), bounded by the timeout.
    let drain = semaphore.acquire_many(max_connections.min(u32::MAX as usize) as u32);
    if timeout(shutdown_timeout, drain).await.is_err() {
        warn!(
            timeout_s = shutdown_timeout.as_secs(),
            "shutdown drain timed out; some connections did not finish"
        );
    }

    let _ = cleanup_handle.await;
    if let Some(handle) = h3_handle {
        let _ = handle.await;
    }

    // Flush, fsync, and join the capture writer last, after all handlers that
    // could write to it have drained, so no capture line is lost or truncated.
    if let Err(e) = shared.captures.shutdown().await {
        warn!(error = %e, "failed to shut down capture writer");
    }

    Ok(())
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
    use uuid::Uuid;

    #[tokio::test]
    async fn run_proxy_bind_fails_when_port_taken() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;

        // run_proxy should return an error since the port is already in use
        let res = run_proxy(addr, cw, shared.cfg.clone()).await;
        assert!(res.is_err());

        let _ = fs::remove_file(&tmp).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_capture_seed_load_error_logs_and_returns_error() -> anyhow::Result<()> {
        // Bind a socket first to reserve the port so run_proxy will fail after startup
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        // Create a path that is a directory so load_captures will error when attempting to open it
        let dir = std::env::temp_dir().join(format!("lint_proxy_seed_dir_{}", Uuid::new_v4()));
        tokio::fs::create_dir(&dir).await?;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.general.captures_seed = true;
        cfg_inner.general.captures = dir.to_string_lossy().to_string();
        let cfg = StdArc::new(cfg_inner);
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None).await?;

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
        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;

        let task = tokio::spawn(async move {
            let _ = run_proxy(addr, cw, shared.cfg.clone()).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        task.abort();
        let _ = task.await;

        tokio::fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_one_connection_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // pick a free port by binding to :0 then dropping the listener
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;

        // spawn the proxy with accept_limit = 1
        let cw_clone = cw.clone();
        let cfg_clone = shared.cfg.clone();
        let task =
            tokio::spawn(
                async move { run_proxy_with_limit(addr, cw_clone, cfg_clone, Some(1)).await },
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
        drop(l);

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;

        let shutdown = CancellationToken::new();
        let cfg_clone = shared.cfg.clone();
        let cw_clone = cw.clone();
        let shutdown_for_task = shutdown.clone();
        let task = tokio::spawn(async move {
            run_proxy_with_shutdown(addr, cw_clone, cfg_clone, shutdown_for_task).await
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
        // pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (_shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;

        // accept_limit = 0 should return quickly
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_proxy_with_limit(addr, cw, _shared.cfg.clone(), Some(0)),
        )
        .await
        .expect("run_proxy_with_limit did not return within timeout")?;

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_with_limit_accepts_two_connections_and_returns() -> anyhow::Result<()> {
        use tokio::net::TcpStream;

        // pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        drop(l);

        let (shared, tmp, cw) =
            make_shared_with_cfg(StdArc::new(crate::config::Config::default()), None).await?;

        let task = tokio::spawn(async move {
            run_proxy_with_limit(addr, cw, shared.cfg.clone(), Some(2)).await
        });

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
        let tmp_capture =
            std::env::temp_dir().join(format!("lint_proxy_seed_ok_{}.jsonl", Uuid::new_v4()));
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
        let (shared, tmp, cw) = make_shared_with_cfg(cfg.clone(), None).await?;

        // run_proxy should attempt to load captures and then fail on bind
        let res = run_proxy(addr, cw, shared.cfg.clone()).await;
        assert!(res.is_err());

        // Cleanup
        let _ = fs::remove_file(&tmp).await;
        let _ = tokio::fs::remove_file(&tmp_capture).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn run_proxy_tls_enabled_starts_and_can_be_aborted() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        // Use temp paths for CA files
        let cert_path = std::env::temp_dir().join(format!("test_ca_run_{}.crt", Uuid::new_v4()));
        let key_path = std::env::temp_dir().join(format!("test_ca_run_{}.key", Uuid::new_v4()));
        cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
        cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

        let cfg = StdArc::new(cfg);
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg.clone(), None).await?;
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

        tokio::fs::remove_file(&cert_path).await?;
        tokio::fs::remove_file(&key_path).await?;
        tokio::fs::remove_file(&tmp).await?;
        Ok(())
    }
}
