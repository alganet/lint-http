// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::Parser;
use std::net::SocketAddr;
use tokio::signal;

use lint_http::{capture, config, proxy};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "lint-http")]
struct Args {
    /// Listen address, e.g. 127.0.0.1:3000
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// Path to append captures JSONL
    #[arg(long, default_value = "captures.jsonl")]
    captures: String,

    /// Optional config YAML path (rules toggles)
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let addr: SocketAddr = args.listen.parse()?;

    let capture_writer = capture::CaptureWriter::new(args.captures).await?;

    // Load config: optional CLI path; defaults if not provided
    let cfg = if let Some(ref p) = args.config {
        config::Config::load_from_path(p).await.unwrap_or_else(|e| {
            warn!(%p, %e, "failed to load config, using defaults");
            config::Config::default()
        })
    } else {
        config::Config::default()
    };

    let cfg = std::sync::Arc::new(cfg);

    let server = proxy::run_proxy(addr, capture_writer, cfg.clone());

    tokio::select! {
        res = server => {
            if let Err(e) = res {
                error!(%e, "server error");
            }
        }
        _ = signal::ctrl_c() => {
            info!("shutting down");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use uuid::Uuid;

    #[tokio::test]
    async fn main_cli_config_loads_toml() {
        let tmp = std::env::temp_dir().join(format!("patina_main_cli_cfg_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
cache-control-present = false
"#;
        fs::write(&tmp, toml).await.expect("write tmp");

        let args = Args {
            listen: "127.0.0.1:0".to_string(),
            captures: tmp.with_extension("jsonl").to_str().unwrap().to_string(),
            config: Some(tmp.to_str().unwrap().to_string()),
        };

        let _addr: SocketAddr = args.listen.parse().expect("parse addr");
        let _cw = capture::CaptureWriter::new(args.captures.clone())
            .await
            .expect("create writer");

        let cfg_path = args
            .config
            .or_else(|| std::env::var("LINT_PROXY_CONFIG").ok());
        let cfg = if let Some(ref p) = cfg_path {
            config::Config::load_from_path(p).await.unwrap_or_default()
        } else {
            config::Config::default()
        };

        assert!(!cfg.is_enabled("cache-control-present"));

        let _ = fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn main_no_config_uses_defaults() {
        let args = Args {
            listen: "127.0.0.1:0".to_string(),
            captures: std::env::temp_dir()
                .join("patina_main_no_cfg.jsonl")
                .to_str()
                .unwrap()
                .to_string(),
            config: None,
        };

        let _addr: SocketAddr = args.listen.parse().expect("parse addr");
        let _cw = capture::CaptureWriter::new(args.captures.clone())
            .await
            .expect("create writer");

        let cfg = if let Some(ref p) = args.config {
            config::Config::load_from_path(p).await.unwrap_or_default()
        } else {
            config::Config::default()
        };

        // defaults should enable rules
        assert!(cfg.is_enabled("cache-control-present"));
    }
}
