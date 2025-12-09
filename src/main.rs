// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::Parser;
use std::net::SocketAddr;
use tokio::signal;

use lint_http::{capture, config, proxy};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "lint-http", version)]
struct Args {
    /// Config TOML path (rules toggles, listen address, captures path)
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let cfg = config::Config::load_from_path(&args.config).await?;
    let cfg = std::sync::Arc::new(cfg);

    let addr: SocketAddr = cfg.general.listen.parse()?;
    let capture_writer = capture::CaptureWriter::new(cfg.general.captures.clone()).await?;

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
    async fn main_cli_config_loads_toml() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_main_cli_cfg_{}.toml", Uuid::new_v4()));
        let toml = r#"[rules]
cache-control-present = false

[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300

[tls]
enabled = false
"#;
        fs::write(&tmp, toml).await?;

        let args = Args {
            config: tmp
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("config path not utf8"))?
                .to_string(),
        };

        let cfg = config::Config::load_from_path(&args.config).await?;

        assert!(!cfg.is_enabled("cache-control-present"));
        // check defaults
        assert_eq!(cfg.general.listen, "127.0.0.1:3000");

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn main_rejects_invalid_rule_config_before_proxy_starts() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_main_cli_cfg_invalid_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.server_clear_site_data]
paths = []  # Invalid: empty paths array
"#;
        fs::write(&tmp, toml).await?;

        // Config load should fail during validation, before any proxy starts
        let result = config::Config::load_from_path(&tmp).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("server_clear_site_data"));
        assert!(err_msg.contains("cannot be empty"));

        fs::remove_file(&tmp).await?;
        Ok(())
    }
}
