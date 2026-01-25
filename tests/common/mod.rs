// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

use lint_http::capture::CaptureWriter;
use lint_http::config::Config;
use lint_http::proxy::run_proxy;
use lint_http::rules::RuleConfigEngine;

// Minimal helper: start run_proxy and wait until it is accepting and CA files exist
pub async fn start_run_proxy_and_wait(
    cfg: Config,
    engine: Arc<RuleConfigEngine>,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, SocketAddr, String)> {
    // prepare capture file
    let tmp = std::env::temp_dir().join(format!("lint_integ_{}.jsonl", uuid::Uuid::new_v4()));
    let p = tmp
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("tmp path not utf8"))?
        .to_string();
    let cw = CaptureWriter::new(p.clone()).await?;

    // Choose a free port by binding then dropping
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);

    let cfg = Arc::new(cfg);
    let cfg_for_spawn = cfg.clone();
    let engine2 = engine.clone();
    let handle = tokio::spawn(async move {
        let _ = run_proxy(addr, cw, cfg_for_spawn, engine2).await;
    });

    // Wait for server to accept connections
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            return Err(anyhow::anyhow!("timeout waiting for proxy to start"));
        }
        if let Ok(mut s) = tokio::net::TcpStream::connect(addr).await {
            let _ = s.shutdown().await;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    // If TLS enabled, wait for CA files
    if cfg.tls.enabled {
        let cert_path = cfg
            .tls
            .ca_cert_path
            .clone()
            .unwrap_or_else(|| "ca.crt".into());
        let key_path = cfg
            .tls
            .ca_key_path
            .clone()
            .unwrap_or_else(|| "ca.key".into());
        let cert_path = std::path::PathBuf::from(cert_path);
        let key_path = std::path::PathBuf::from(key_path);
        let deadline2 = Instant::now() + Duration::from_secs(5);
        loop {
            if cert_path.exists() && key_path.exists() {
                break;
            }
            if Instant::now() > deadline2 {
                return Err(anyhow::anyhow!("timeout waiting for CA files"));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    Ok((handle, addr, p))
}
