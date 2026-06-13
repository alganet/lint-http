// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP proxy server implementation with request forwarding and capture.

mod body;
mod connect;
mod hop_by_hop;
mod http;
mod http3;
mod pipeline;
#[cfg(test)]
mod test_support;
mod websocket;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{service::service_fn, Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{error, info};

use crate::ca::CertificateAuthority;
use crate::capture::CaptureWriter;
use crate::config::Config;

use self::http::handle_request;
use self::http3::{init_h3_endpoint, run_h3_accept_loop};

pub(super) type ServiceFuture =
    Pin<Box<dyn Future<Output = Result<Response<BoxBody<Bytes, Infallible>>, Infallible>> + Send>>;

pub(super) struct Shared {
    pub(super) client: LegacyClient<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<bytes::Bytes>,
    >,
    pub(super) captures: CaptureWriter,
    pub(super) cfg: Arc<Config>,
    pub(super) state: Arc<crate::state::StateStore>,
    pub(super) protocol_event_store: Arc<crate::protocol_event_store::ProtocolEventStore>,
    pub(super) ca: Option<Arc<CertificateAuthority>>,
    pub(super) quic_transport_params: Option<crate::protocol_event::QuicTransportParameters>,
}

pub async fn run_proxy(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
) -> anyhow::Result<()> {
    // Default behavior: no accept limit (runs forever)
    run_proxy_with_limit(listen, captures, cfg, None).await
}

/// Testable variant of `run_proxy` that accepts an optional `accept_limit`.
/// When `accept_limit` is `Some(n)`, the accept loop will accept `n` connections
/// and then return after accepting the Nth connection. Connection handlers are
/// spawned asynchronously and may still be running when this function returns,
/// allowing tests to deterministically bound how many connections are accepted.
pub async fn run_proxy_with_limit(
    listen: SocketAddr,
    captures: CaptureWriter,
    cfg: Arc<Config>,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: LegacyClient<_, http_body_util::Full<bytes::Bytes>> =
        LegacyClient::builder(TokioExecutor::new()).build(https);

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
    if cfg.general.captures_seed {
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

    // Spawn background cleanup task
    let state_cleanup = state.clone();
    let pe_store_cleanup = protocol_event_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            state_cleanup.cleanup_expired();
            pe_store_cleanup.cleanup_expired();
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

    let shared = Arc::new(Shared {
        client,
        captures,
        cfg,
        state,
        protocol_event_store,
        ca,
        quic_transport_params,
    });

    // Start HTTP/3 (QUIC) accept loop if an endpoint was created.
    if let Some(endpoint) = h3_endpoint {
        let shared_h3 = shared.clone();
        tokio::spawn(async move {
            run_h3_accept_loop(endpoint, shared_h3).await;
        });
    }

    // Use a manual TcpListener accept loop to preserve the remote address and
    // avoid relying on the removed `make_service_fn` helper in hyper v1.
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "listening");

    let executor = TokioExecutor::new();
    let server_builder = AutoConnBuilder::new(executor);

    // Accept loop with optional limit
    let mut remaining = accept_limit;
    loop {
        // If we're limited and have reached zero, stop accepting
        if let Some(0) = remaining {
            break;
        }

        let (stream, remote_addr) = listener.accept().await?;

        // Decrement remaining if present
        if let Some(ref mut n) = remaining {
            *n -= 1;
        }

        let shared = shared.clone();
        let builder_clone = server_builder.clone();
        tokio::spawn(async move {
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
            if let Err(e) = builder_clone
                .serve_connection_with_upgrades(io, service)
                .await
            {
                error!(%e, "connection error");
            }
        });
    }

    Ok(())
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
