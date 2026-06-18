// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::{Parser, Subcommand};
use std::net::SocketAddr;

use lint_http::{capture, config, proxy, rules};

#[derive(Parser, Debug)]
#[command(name = "lint-http", version, about = "HTTP-linting forward proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Deprecated: use `lint-http run --config <PATH>`.
    #[arg(long, value_name = "PATH", hide = true)]
    config: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the intercepting proxy (config-driven).
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Config TOML path (rules toggles, listen address, captures path).
    #[arg(long)]
    config: String,
}

/// Load + validate the config and build the proxy's runtime inputs.
///
/// Takes the config *path* rather than the parsed CLI struct, so the proxy entry
/// points are decoupled from the command surface. This step is proxy-specific
/// (it initializes tracing and builds a `CaptureWriter`); future non-proxy
/// subcommands (`lint`, `rules list`) reuse the library helpers
/// `config::Config::load_from_path` / `rules::validate_rules` directly rather
/// than this.
async fn load_and_prepare(
    config_path: &str,
) -> anyhow::Result<(
    SocketAddr,
    capture::CaptureWriter,
    std::sync::Arc<config::Config>,
)> {
    let _ = tracing_subscriber::fmt::try_init();

    let cfg = config::Config::load_from_path(config_path).await?;
    // Validate every enabled rule's config section before binding, so a
    // malformed config fails fast rather than after the proxy is up.
    rules::validate_rules(&cfg)?;
    let cfg = std::sync::Arc::new(cfg);

    let addr: SocketAddr = cfg.general.listen.parse()?;
    let capture_writer = capture::CaptureWriter::new(
        cfg.general.captures.clone(),
        cfg.general.captures_include_body,
    )
    .await?;

    Ok((addr, capture_writer, cfg))
}

/// Run the proxy until Ctrl-C / shutdown.
async fn run_app(config_path: &str) -> anyhow::Result<()> {
    let (addr, capture_writer, cfg) = load_and_prepare(config_path).await?;
    // `run_proxy` wires Ctrl-C to a graceful shutdown.
    proxy::run_proxy(addr, capture_writer, cfg).await
}

// Testable variant of run_app that allows tests to pass in an accept limit so the
// proxy returns after a bounded number of connections.
#[cfg(test)]
async fn run_app_with_limit(config_path: &str, accept_limit: Option<usize>) -> anyhow::Result<()> {
    let (addr, capture_writer, cfg) = load_and_prepare(config_path).await?;
    crate::proxy::run_proxy_with_limit(addr, capture_writer, cfg, accept_limit).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = match cli.command {
        Some(Command::Run(args)) => args.config,
        // No subcommand: accept a bare `--config` as a deprecated alias for
        // `run`, otherwise point the user at the new form.
        None => {
            let path = cli.config.ok_or_else(|| {
                anyhow::anyhow!(
                    "no command given; try `lint-http run --config <PATH>` (see `lint-http --help`)"
                )
            })?;
            eprintln!(
                "warning: bare `--config` is deprecated; use `lint-http run --config {path}`"
            );
            path
        }
    };
    run_app(&config_path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tokio::fs;
    use uuid::Uuid;

    #[test]
    fn cli_run_subcommand_parses_config() {
        let cli = Cli::parse_from(["lint-http", "run", "--config", "x.toml"]);
        match cli.command {
            Some(Command::Run(args)) => assert_eq!(args.config, "x.toml"),
            other => panic!("expected Run, got {other:?}"),
        }
        assert!(cli.config.is_none());
    }

    #[test]
    fn cli_bare_config_is_legacy_alias() {
        let cli = Cli::parse_from(["lint-http", "--config", "x.toml"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.config.as_deref(), Some("x.toml"));
    }

    #[test]
    fn cli_no_args_has_no_command() {
        let cli = Cli::parse_from(["lint-http"]);
        assert!(cli.command.is_none());
        assert!(cli.config.is_none());
    }

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

        let config_path = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("config path not utf8"))?;

        let cfg = config::Config::load_from_path(config_path).await?;

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

        let config_path = tmp.to_str().expect("valid utf8 path");

        // run_app must fail during rule validation, before binding any socket.
        let result = run_app(config_path).await;

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

        let config_path = tmp.to_str().expect("valid utf8 path").to_string();

        // Spawn run_app_with_limit with accept_limit = 1
        let task = tokio::spawn(async move { run_app_with_limit(&config_path, Some(1)).await });

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

        let config_path = tmp.to_str().expect("valid utf8 path");

        // run_app should return an error because the port is already taken
        let res = run_app(config_path).await;
        assert!(res.is_err());

        // Cleanup
        let _ = tokio::fs::remove_file(&tmp).await;
        let _ = tokio::fs::remove_file(&capture_path).await;
        drop(l);
        Ok(())
    }
}
