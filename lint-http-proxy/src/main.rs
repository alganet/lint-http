// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::{Parser, Subcommand};
use std::net::SocketAddr;

use lint_http::{capture, config, engine, lint, proxy, rules, state};

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
    /// Lint a recorded capture file, replaying its transactions through the rules.
    Lint(LintArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Config TOML path (rules toggles, listen address, captures path).
    #[arg(long)]
    config: String,
}

#[derive(clap::Args, Debug)]
struct LintArgs {
    /// Config TOML path (rule toggles + severities; also supplies the replay
    /// state's `ttl_seconds` / `max_history`).
    #[arg(long)]
    config: String,
    /// JSONL capture file to lint.
    #[arg(value_name = "CAPTURES")]
    captures: String,
}

/// Load the config and validate every enabled rule's section, failing fast on a
/// malformed config. Shared by every subcommand; deliberately does **not**
/// initialize tracing (the proxy does that) so non-proxy commands like `lint`
/// keep stdout clean.
async fn load_validated_config(
    config_path: &str,
) -> anyhow::Result<std::sync::Arc<config::Config>> {
    let cfg = config::Config::load_from_path(config_path).await?;
    rules::validate_rules(&cfg)?;
    Ok(std::sync::Arc::new(cfg))
}

/// Load + validate the config and build the proxy's runtime inputs.
///
/// Proxy-specific: it initializes tracing and builds a `CaptureWriter`. Takes the
/// config *path* rather than the parsed CLI struct, so the proxy entry points are
/// decoupled from the command surface.
async fn load_and_prepare(
    config_path: &str,
) -> anyhow::Result<(
    SocketAddr,
    capture::CaptureWriter,
    std::sync::Arc<config::Config>,
)> {
    let _ = tracing_subscriber::fmt::try_init();

    let cfg = load_validated_config(config_path).await?;

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

fn severity_label(severity: lint::Severity) -> &'static str {
    match severity {
        lint::Severity::Info => "info",
        lint::Severity::Warn => "warn",
        lint::Severity::Error => "error",
    }
}

/// Lint a recorded capture file by replaying its transactions through the rule
/// engine, printing violations to stdout. Returns the number of violations found
/// so the caller can map it to an exit code.
///
/// The replay mirrors the live proxy pipeline: each transaction is linted against
/// the history of prior transactions, then recorded — so stateful rules see the
/// same history they would live. The state store's TTL never evicts here (the
/// read path applies no age filter and `cleanup_expired` is never called), so the
/// whole file is visible regardless of how old the records are.
async fn lint_app(config_path: &str, captures_path: &str) -> anyhow::Result<usize> {
    let cfg = load_validated_config(config_path).await?;
    // `load_captures` tolerates a missing file (it backs the proxy's optional
    // cold-start seeding). For an explicit `lint <file>` a missing path is a user
    // error — fail loudly rather than letting CI pass green on a typo'd path.
    if !tokio::fs::try_exists(captures_path).await.unwrap_or(false) {
        anyhow::bail!("capture file not found: {captures_path}");
    }
    let transactions = capture::load_captures(captures_path).await?;
    let state = state::StateStore::new(cfg.general.ttl_seconds, cfg.general.max_history);

    let mut total = 0usize;
    for tx in &transactions {
        let violations = engine::lint_transaction(tx, &cfg, &state);
        state.record_transaction(tx);
        if violations.is_empty() {
            continue;
        }
        let status = tx
            .response
            .as_ref()
            .map(|r| r.status.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!("{} {} -> {}", tx.request.method, tx.request.uri, status);
        for v in &violations {
            println!(
                "  {:<5} {}  {}",
                severity_label(v.severity),
                v.rule,
                v.message
            );
        }
        total += violations.len();
    }

    println!(
        "\n{total} violation(s) in {} transaction(s)",
        transactions.len()
    );
    Ok(total)
}

/// Run the selected subcommand and return the process exit code (`0` success,
/// `1` lint findings). Real errors propagate as `Err` (anyhow maps them to exit
/// 1 with a message). Split from `main` so the dispatch is unit-testable without
/// spawning the process.
async fn dispatch(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Some(Command::Run(args)) => {
            run_app(&args.config).await?;
            Ok(0)
        }
        // Non-zero exit when findings exist, so CI fails on a dirty capture;
        // real errors (bad config / missing file) still bubble up as `Err`.
        Some(Command::Lint(args)) => {
            let found = lint_app(&args.config, &args.captures).await?;
            Ok(if found > 0 { 1 } else { 0 })
        }
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
            run_app(&path).await?;
            Ok(0)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    Ok(std::process::ExitCode::from(dispatch(Cli::parse()).await?))
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

    #[test]
    fn cli_lint_subcommand_parses_config_and_captures() {
        let cli = Cli::parse_from(["lint-http", "lint", "--config", "c.toml", "caps.jsonl"]);
        match cli.command {
            Some(Command::Lint(args)) => {
                assert_eq!(args.config, "c.toml");
                assert_eq!(args.captures, "caps.jsonl");
            }
            other => panic!("expected Lint, got {other:?}"),
        }
    }

    // Write a config that enables `server_cache_control_present` (fires on a 200
    // response without a Cache-Control header) and return its temp path.
    async fn write_cache_control_config() -> anyhow::Result<std::path::PathBuf> {
        let tmp = std::env::temp_dir().join(format!("lint_lint_cfg_{}.toml", Uuid::new_v4()));
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.server_cache_control_present]
enabled = true
severity = "warn"
"#;
        fs::write(&tmp, toml).await?;
        Ok(tmp)
    }

    // Serialize transactions into a JSONL capture file (one versioned envelope per
    // line) the way the proxy's CaptureWriter would, and return its temp path.
    async fn write_capture_file(
        txs: &[lint_http::http_transaction::HttpTransaction],
    ) -> anyhow::Result<std::path::PathBuf> {
        let tmp = std::env::temp_dir().join(format!("lint_lint_caps_{}.jsonl", Uuid::new_v4()));
        let mut body = String::new();
        for tx in txs {
            let envelope = capture::CaptureEnvelope {
                schema_version: capture::CAPTURE_SCHEMA_VERSION,
                record: capture::CaptureRecord::HttpTransaction(Box::new(tx.clone())),
            };
            body.push_str(&serde_json::to_string(&envelope)?);
            body.push('\n');
        }
        fs::write(&tmp, body).await?;
        Ok(tmp)
    }

    #[tokio::test]
    async fn lint_reports_violations_and_counts_them() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let cfg = write_cache_control_config().await?;
        // 200 without Cache-Control -> one violation.
        let caps = write_capture_file(&[make_test_transaction_with_response(200, &[])]).await?;

        let found = lint_app(cfg.to_str().unwrap(), caps.to_str().unwrap()).await?;
        assert_eq!(found, 1);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_clean_capture_reports_zero() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let cfg = write_cache_control_config().await?;
        // 200 *with* Cache-Control -> the rule is satisfied, no violation.
        let caps = write_capture_file(&[make_test_transaction_with_response(
            200,
            &[("cache-control", "no-store")],
        )])
        .await?;

        let found = lint_app(cfg.to_str().unwrap(), caps.to_str().unwrap()).await?;
        assert_eq!(found, 0);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_empty_capture_reports_zero() -> anyhow::Result<()> {
        let cfg = write_cache_control_config().await?;
        let caps = std::env::temp_dir().join(format!("lint_lint_empty_{}.jsonl", Uuid::new_v4()));
        fs::write(&caps, "").await?;

        let found = lint_app(cfg.to_str().unwrap(), caps.to_str().unwrap()).await?;
        assert_eq!(found, 0);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_missing_capture_file_errors() -> anyhow::Result<()> {
        let cfg = write_cache_control_config().await?;
        let result = lint_app(cfg.to_str().unwrap(), "/nonexistent/does-not-exist.jsonl").await;
        assert!(result.is_err());

        fs::remove_file(&cfg).await?;
        Ok(())
    }

    #[test]
    fn severity_label_covers_all_levels() {
        assert_eq!(severity_label(lint::Severity::Info), "info");
        assert_eq!(severity_label(lint::Severity::Warn), "warn");
        assert_eq!(severity_label(lint::Severity::Error), "error");
    }

    // Write a minimal config whose `listen` points at an already-bound port, so
    // `run_app` fails fast at bind — lets the dispatch tests exercise the `run`
    // and legacy arms without the proxy blocking.
    async fn write_port_taken_config(
        addr: std::net::SocketAddr,
    ) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
        let cfg = std::env::temp_dir().join(format!("lint_dispatch_cfg_{}.toml", Uuid::new_v4()));
        let caps =
            std::env::temp_dir().join(format!("lint_dispatch_caps_{}.jsonl", Uuid::new_v4()));
        let toml = format!(
            "[general]\nlisten = \"{addr}\"\ncaptures = \"{caps}\"\n\n[tls]\nenabled = false\n",
            addr = addr,
            caps = caps.to_string_lossy()
        );
        fs::write(&cfg, toml).await?;
        Ok((cfg, caps))
    }

    #[tokio::test]
    async fn dispatch_lint_findings_returns_exit_1() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;
        let cfg = write_cache_control_config().await?;
        let caps = write_capture_file(&[make_test_transaction_with_response(200, &[])]).await?;
        let cli = Cli::parse_from([
            "lint-http",
            "lint",
            "--config",
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
        ]);
        assert_eq!(dispatch(cli).await?, 1);
        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_lint_clean_returns_exit_0() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;
        let cfg = write_cache_control_config().await?;
        let caps = write_capture_file(&[make_test_transaction_with_response(
            200,
            &[("cache-control", "no-store")],
        )])
        .await?;
        let cli = Cli::parse_from([
            "lint-http",
            "lint",
            "--config",
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
        ]);
        assert_eq!(dispatch(cli).await?, 0);
        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_no_command_errors() {
        let cli = Cli::parse_from(["lint-http"]);
        assert!(dispatch(cli).await.is_err());
    }

    #[tokio::test]
    async fn dispatch_run_command_routes_to_run_app() -> anyhow::Result<()> {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        let (cfg, caps) = write_port_taken_config(addr).await?;
        let cli = Cli::parse_from(["lint-http", "run", "--config", cfg.to_str().unwrap()]);
        // run_app binds the already-taken port and errors fast.
        assert!(dispatch(cli).await.is_err());
        let _ = fs::remove_file(&cfg).await;
        let _ = fs::remove_file(&caps).await;
        drop(l);
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_legacy_config_routes_to_run_app() -> anyhow::Result<()> {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        let (cfg, caps) = write_port_taken_config(addr).await?;
        let cli = Cli::parse_from(["lint-http", "--config", cfg.to_str().unwrap()]);
        // Legacy bare --config routes to run_app, which errors on the taken port.
        assert!(dispatch(cli).await.is_err());
        let _ = fs::remove_file(&cfg).await;
        let _ = fs::remove_file(&caps).await;
        drop(l);
        Ok(())
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
