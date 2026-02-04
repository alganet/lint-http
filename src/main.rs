// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::Parser;
use std::net::SocketAddr;

use lint_http::{capture, config, proxy};

#[derive(Parser, Debug)]
#[command(name = "lint-http", version)]
struct Args {
    /// Config TOML path (rules toggles, listen address, captures path)
    #[arg(long)]
    config: String,
}

/// Simplified application entry point.
async fn run_app(args: Args) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let (cfg, engine) = config::Config::load_from_path(&args.config).await?;
    let cfg = std::sync::Arc::new(cfg);
    let engine = std::sync::Arc::new(engine);

    let addr: SocketAddr = cfg.general.listen.parse()?;
    let capture_writer = capture::CaptureWriter::new(
        cfg.general.captures.clone(),
        cfg.general.captures_include_body,
    )
    .await?;

    // Start proxy and return its result (no signal handling here).
    proxy::run_proxy(addr, capture_writer, cfg, engine).await
}

// Testable variant of run_app that allows tests to pass in an accept limit so the
// proxy returns after a bounded number of connections.
#[cfg(test)]
async fn run_app_with_limit(args: Args, accept_limit: Option<usize>) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let (cfg, engine) = config::Config::load_from_path(&args.config).await?;
    let cfg = std::sync::Arc::new(cfg);
    let engine = std::sync::Arc::new(engine);

    let addr: SocketAddr = cfg.general.listen.parse()?;
    let capture_writer = capture::CaptureWriter::new(
        cfg.general.captures.clone(),
        cfg.general.captures_include_body,
    )
    .await?;

    // Start proxy with an accept limit for testing
    crate::proxy::run_proxy_with_limit(addr, capture_writer, cfg, engine, accept_limit).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run_app(args).await
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
    [rules.server_cache_control_present]
    enabled = false
    severity = "warn"

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

        let (cfg, _engine) = config::Config::load_from_path(&args.config).await?;

        assert!(!cfg.is_enabled("server_cache_control_present"));
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
 enabled = true
 severity = "warn"
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

    #[tokio::test]
    async fn run_app_with_limit_starts_and_returns() -> anyhow::Result<()> {
        // Pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = l.local_addr()?.port();
        drop(l);

        let tmp =
            std::env::temp_dir().join(format!("lint_main_with_limit_{}.toml", Uuid::new_v4()));
        let capture_path = std::env::temp_dir().join(format!("captures_{}.jsonl", Uuid::new_v4()));
        let toml = format!(
            r#"[rules]
[rules.server_cache_control_present]
enabled = false
severity = "warn"

[general]
listen = "127.0.0.1:{port}"
captures = "{captures}"
ttl_seconds = 300

[tls]
enabled = false
"#,
            port = port,
            captures = capture_path.to_string_lossy()
        );
        fs::write(&tmp, toml).await?;

        let args = Args {
            config: tmp.to_str().expect("valid utf8 path").to_string(),
        };

        // Spawn run_app_with_limit with accept_limit = 1
        let task = tokio::spawn(async move { run_app_with_limit(args, Some(1)).await });

        // Connect to trigger accept
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
        let mut connected = false;
        for _ in 0..20 {
            if let Ok(_s) = tokio::net::TcpStream::connect(addr).await {
                connected = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(connected, "failed to connect to run_app server");

        // wait for task to finish
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), task).await??;
        assert!(res.is_ok());

        let _ = fs::remove_file(&tmp).await;
        let _ = tokio::fs::remove_file(&capture_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn run_app_errors_when_port_taken() -> anyhow::Result<()> {
        // Reserve a port by binding a TcpListener
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let tmp =
            std::env::temp_dir().join(format!("lint_main_port_taken_{}.toml", Uuid::new_v4()));
        let capture_path = std::env::temp_dir().join(format!("captures_{}.jsonl", Uuid::new_v4()));
        let toml = format!(
            r#"[rules]
[rules.server_cache_control_present]
enabled = false
severity = "warn"

[general]
listen = "{addr}"
captures = "{captures}"
ttl_seconds = 300

[tls]
enabled = false
"#,
            addr = addr,
            captures = capture_path.to_string_lossy()
        );
        tokio::fs::write(&tmp, toml).await?;

        let args = Args {
            config: tmp.to_str().expect("valid utf8 path").to_string(),
        };

        // run_app should return an error because the port is already taken
        let res = run_app(args).await;
        assert!(res.is_err());

        // Cleanup
        let _ = tokio::fs::remove_file(&tmp).await;
        let _ = tokio::fs::remove_file(&capture_path).await;
        drop(l);
        Ok(())
    }
}
