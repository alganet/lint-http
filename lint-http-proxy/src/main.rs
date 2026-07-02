// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

use lint_http::{capture, config, engine, gendocs, lint, proxy, rules, state};

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
    /// Inspect the rule catalogue.
    Rules(RulesArgs),
    /// Regenerate the rule documentation under <out>/ from rule metadata.
    Gendocs(GendocsArgs),
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Only report findings at or above this severity; the exit code follows
    /// the gated set (0 when everything below the gate is filtered out).
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    min_severity: SeverityArg,
    /// JSONL capture file to lint.
    #[arg(value_name = "CAPTURES")]
    captures: String,
}

/// CLI mirror of [`lint::Severity`] (which lives in core and doesn't know clap).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum SeverityArg {
    Info,
    Warn,
    Error,
}

impl From<SeverityArg> for lint::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => lint::Severity::Info,
            SeverityArg::Warn => lint::Severity::Warn,
            SeverityArg::Error => lint::Severity::Error,
        }
    }
}

#[derive(clap::Args, Debug)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand, Debug)]
enum RulesCommand {
    /// List every rule and its metadata.
    List(RulesListArgs),
}

#[derive(clap::Args, Debug)]
struct RulesListArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Config TOML path; when given, each rule is annotated with whether that
    /// config enables it (a text column / JSON `enabled` field).
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(clap::Args, Debug)]
struct GendocsArgs {
    /// Output directory; `rules.md` and `rules/<id>.md` are written under it.
    #[arg(long, default_value = "docs")]
    out: std::path::PathBuf,
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

/// Write to stdout, treating a closed pipe as a clean exit. Rust ignores
/// `SIGPIPE`, so writing to a reader that has gone away (e.g. `rules list | head`)
/// surfaces as a `BrokenPipe` error that `print!`/`println!` turn into a panic;
/// the 184-line catalogue is routinely piped, so swallow that one error kind.
fn write_stdout(s: &str) -> anyhow::Result<()> {
    use std::io::Write;
    match std::io::stdout().write_all(s.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

fn scope_label(scope: rules::RuleScope) -> &'static str {
    match scope {
        rules::RuleScope::Client => "client",
        rules::RuleScope::Server => "server",
        rules::RuleScope::Both => "both",
    }
}

/// One rule's metadata, flattened for `rules list --format json`. Protocol rules
/// have no scope, so they are labelled `"protocol"`. `enabled` is populated only
/// when the caller supplied a `--config` to consult (and omitted from the JSON
/// otherwise, so the config-less output is unchanged).
#[derive(serde::Serialize)]
struct RuleInfo {
    id: &'static str,
    kind: &'static str,
    scope: &'static str,
    title: Option<&'static str>,
    description: &'static str,
    rfc_references: &'static [&'static str],
    examples: Vec<ExampleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
}

/// serde mirror of [`rules::Example`] (which lives below the serialization
/// boundary and doesn't derive it).
#[derive(serde::Serialize)]
struct ExampleInfo {
    compliance: &'static str,
    label: Option<&'static str>,
    snippet: &'static str,
}

fn example_info(examples: &'static [rules::Example]) -> Vec<ExampleInfo> {
    examples
        .iter()
        .map(|e| ExampleInfo {
            compliance: match e.compliance {
                rules::Compliance::Compliant => "compliant",
                rules::Compliance::NonCompliant => "non_compliant",
            },
            label: e.label,
            snippet: e.snippet,
        })
        .collect()
}

/// Collect every transaction rule then every protocol rule, each already
/// id-sorted by its `LazyLock` view. `cfg` (from `--config`) fills `enabled`.
fn collect_rule_info(cfg: Option<&config::Config>) -> Vec<RuleInfo> {
    let mut infos: Vec<RuleInfo> = rules::RULES
        .iter()
        .map(|r| RuleInfo {
            id: r.id(),
            kind: "transaction",
            scope: scope_label(r.scope()),
            title: r.title(),
            description: r.description(),
            rfc_references: r.rfc_references(),
            examples: example_info(r.examples()),
            enabled: cfg.map(|c| c.is_enabled(r.id())),
        })
        .collect();
    infos.extend(rules::PROTOCOL_RULES.iter().map(|r| RuleInfo {
        id: r.id(),
        kind: "protocol",
        scope: "protocol",
        title: r.title(),
        description: r.description(),
        rfc_references: r.rfc_references(),
        examples: example_info(r.examples()),
        enabled: cfg.map(|c| c.is_enabled(r.id())),
    }));
    infos
}

/// Render the rule catalogue. Returns the output string so the dispatch arm can
/// print it (and tests can assert on it). Needs no proxy; `cfg` is present only
/// when the user asked for the enabled/disabled annotation.
fn rules_list(format: OutputFormat, cfg: Option<&config::Config>) -> anyhow::Result<String> {
    let infos = collect_rule_info(cfg);
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&infos)?),
        OutputFormat::Text => {
            use std::fmt::Write;
            let mut out = String::new();
            for info in &infos {
                write!(out, "{:<60}", info.id)?;
                if let Some(enabled) = info.enabled {
                    write!(out, " {:<8}", if enabled { "enabled" } else { "disabled" })?;
                }
                // Most rules have no title override; omit the field entirely so
                // those lines don't carry a trailing space.
                match info.title {
                    Some(title) => writeln!(out, " [{}] {}", info.scope, title)?,
                    None => writeln!(out, " [{}]", info.scope)?,
                }
            }
            Ok(out)
        }
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
async fn lint_app(
    config_path: &str,
    captures_path: &str,
    format: OutputFormat,
    min_severity: lint::Severity,
) -> anyhow::Result<usize> {
    let cfg = load_validated_config(config_path).await?;
    // `load_captures` tolerates a missing file (it backs the proxy's optional
    // cold-start seeding). For an explicit `lint <file>` a missing path is a user
    // error — fail loudly rather than letting CI pass green on a typo'd path.
    if !tokio::fs::try_exists(captures_path).await.unwrap_or(false) {
        anyhow::bail!("capture file not found: {captures_path}");
    }
    let transactions = capture::load_captures(captures_path).await?;
    let state = state::StateStore::new(cfg.general.ttl_seconds, cfg.general.max_history);
    // Precompute the enabled rule set once, then reuse it across the replay.
    let engine = engine::PreparedEngine::new(&cfg);

    let mut findings = Vec::new();
    for tx in &transactions {
        let mut violations = engine.lint_transaction(tx, &cfg, &state);
        // Record *before* gating: stateful rules must see every transaction in
        // the file regardless of what the report includes.
        state.record_transaction(tx);
        violations.retain(|v| v.severity >= min_severity);
        if violations.is_empty() {
            continue;
        }
        findings.push(TransactionFindings {
            method: tx.request.method.clone(),
            uri: tx.request.uri.clone(),
            status: tx.response.as_ref().map(|r| r.status),
            violations,
        });
    }

    let total = findings.iter().map(|f| f.violations.len()).sum();
    write_stdout(&render_lint_report(
        &findings,
        total,
        transactions.len(),
        format,
    )?)?;
    Ok(total)
}

/// One transaction's surviving findings, for `lint` output. The JSON form
/// mirrors the text block: request line fields plus the violation list
/// (`status` is `null` for transactions that never got a response).
#[derive(serde::Serialize)]
struct TransactionFindings {
    method: String,
    uri: String,
    status: Option<u16>,
    violations: Vec<lint::Violation>,
}

/// Render the `lint` report: the text form ends with a human summary line; the
/// JSON form is a bare array of [`TransactionFindings`] so it stays
/// machine-parseable.
fn render_lint_report(
    findings: &[TransactionFindings],
    total: usize,
    transaction_count: usize,
    format: OutputFormat,
) -> anyhow::Result<String> {
    match format {
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(findings)?)),
        OutputFormat::Text => {
            use std::fmt::Write;
            let mut out = String::new();
            for f in findings {
                let status = f
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string());
                writeln!(out, "{} {} -> {}", f.method, f.uri, status)?;
                for v in &f.violations {
                    writeln!(
                        out,
                        "  {:<5} {}  {}",
                        severity_label(v.severity),
                        v.rule,
                        v.message
                    )?;
                }
            }
            writeln!(
                out,
                "\n{total} violation(s) in {transaction_count} transaction(s)"
            )?;
            Ok(out)
        }
    }
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
            let found = lint_app(
                &args.config,
                &args.captures,
                args.format,
                args.min_severity.into(),
            )
            .await?;
            Ok(if found > 0 { 1 } else { 0 })
        }
        Some(Command::Rules(args)) => match args.command {
            RulesCommand::List(a) => {
                let cfg = match &a.config {
                    Some(path) => Some(load_validated_config(path).await?),
                    None => None,
                };
                write_stdout(&rules_list(a.format, cfg.as_deref())?)?;
                Ok(0)
            }
        },
        Some(Command::Gendocs(args)) => {
            gendocs::write_all(&args.out)?;
            eprintln!("Wrote rule docs to {}", args.out.display());
            Ok(0)
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

        let found = lint_app(
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await?;
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

        let found = lint_app(
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await?;
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

        let found = lint_app(
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await?;
        assert_eq!(found, 0);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_missing_capture_file_errors() -> anyhow::Result<()> {
        let cfg = write_cache_control_config().await?;
        let result = lint_app(
            cfg.to_str().unwrap(),
            "/nonexistent/does-not-exist.jsonl",
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await;
        assert!(result.is_err());

        fs::remove_file(&cfg).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_min_severity_gates_findings_and_exit_code() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        // The config rates the rule `warn`, so an `error` gate filters it out…
        let cfg = write_cache_control_config().await?;
        let caps = write_capture_file(&[make_test_transaction_with_response(200, &[])]).await?;

        let found = lint_app(
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Error,
        )
        .await?;
        assert_eq!(found, 0, "warn finding must not survive an error gate");

        // …while a `warn` gate keeps it.
        let found = lint_app(
            cfg.to_str().unwrap(),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Warn,
        )
        .await?;
        assert_eq!(found, 1);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&caps).await?;
        Ok(())
    }

    #[test]
    fn cli_lint_parses_format_and_min_severity() {
        let cli = Cli::parse_from([
            "lint-http",
            "lint",
            "--config",
            "c.toml",
            "--format",
            "json",
            "--min-severity",
            "warn",
            "caps.jsonl",
        ]);
        match cli.command {
            Some(Command::Lint(args)) => {
                assert!(matches!(args.format, OutputFormat::Json));
                assert!(matches!(args.min_severity, SeverityArg::Warn));
            }
            other => panic!("expected Lint, got {other:?}"),
        }
    }

    #[test]
    fn cli_lint_defaults_to_text_and_info() {
        let cli = Cli::parse_from(["lint-http", "lint", "--config", "c.toml", "caps.jsonl"]);
        match cli.command {
            Some(Command::Lint(args)) => {
                assert!(matches!(args.format, OutputFormat::Text));
                assert!(matches!(args.min_severity, SeverityArg::Info));
            }
            other => panic!("expected Lint, got {other:?}"),
        }
    }

    fn sample_findings() -> Vec<TransactionFindings> {
        vec![TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![lint::Violation {
                rule: "server_cache_control_present".to_string(),
                severity: lint::Severity::Warn,
                message: "missing Cache-Control".to_string(),
            }],
        }]
    }

    #[test]
    fn render_lint_report_json_mirrors_the_text_block() -> anyhow::Result<()> {
        let out = render_lint_report(&sample_findings(), 1, 3, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["method"], "GET");
        assert_eq!(parsed[0]["status"], 200);
        assert_eq!(
            parsed[0]["violations"][0]["rule"],
            "server_cache_control_present"
        );
        assert_eq!(parsed[0]["violations"][0]["severity"], "warn");
        Ok(())
    }

    #[test]
    fn render_lint_report_json_null_status_for_no_response() -> anyhow::Result<()> {
        let mut findings = sample_findings();
        findings[0].status = None;
        let out = render_lint_report(&findings, 1, 1, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        assert!(parsed[0]["status"].is_null());
        Ok(())
    }

    #[test]
    fn render_lint_report_text_has_summary_line() -> anyhow::Result<()> {
        let out = render_lint_report(&sample_findings(), 1, 3, OutputFormat::Text)?;
        assert!(out.contains("GET http://example.test/ -> 200"));
        assert!(out.contains("warn  server_cache_control_present"));
        assert!(out.ends_with("1 violation(s) in 3 transaction(s)\n"));
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

    #[test]
    fn cli_rules_list_parses_format() {
        let cli = Cli::parse_from(["lint-http", "rules", "list", "--format", "json"]);
        match cli.command {
            Some(Command::Rules(args)) => match args.command {
                RulesCommand::List(a) => assert!(matches!(a.format, OutputFormat::Json)),
            },
            other => panic!("expected Rules(List), got {other:?}"),
        }
    }

    #[test]
    fn cli_rules_list_defaults_to_text() {
        let cli = Cli::parse_from(["lint-http", "rules", "list"]);
        match cli.command {
            Some(Command::Rules(args)) => match args.command {
                RulesCommand::List(a) => assert!(matches!(a.format, OutputFormat::Text)),
            },
            other => panic!("expected Rules(List), got {other:?}"),
        }
    }

    #[test]
    fn cli_gendocs_parses_out() {
        let cli = Cli::parse_from(["lint-http", "gendocs", "--out", "/tmp/x"]);
        match cli.command {
            Some(Command::Gendocs(args)) => {
                assert_eq!(args.out, std::path::PathBuf::from("/tmp/x"))
            }
            other => panic!("expected Gendocs, got {other:?}"),
        }
    }

    #[test]
    fn scope_label_covers_all_variants() {
        assert_eq!(scope_label(rules::RuleScope::Client), "client");
        assert_eq!(scope_label(rules::RuleScope::Server), "server");
        assert_eq!(scope_label(rules::RuleScope::Both), "both");
    }

    #[test]
    fn rules_list_text_includes_a_known_rule() -> anyhow::Result<()> {
        let out = rules_list(OutputFormat::Text, None)?;
        // The catalogue lists transaction and protocol rules with a scope label.
        assert!(out.contains("server_cache_control_present"));
        assert!(out.contains("[server]"));
        // Protocol rules are labelled `protocol`.
        assert!(out.contains("[protocol]"));
        // Without a config there is no enabled/disabled column.
        assert!(!out.contains("enabled"));
        Ok(())
    }

    #[test]
    fn rules_list_json_is_an_array_of_metadata() -> anyhow::Result<()> {
        let out = rules_list(OutputFormat::Json, None)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        assert!(!parsed.is_empty());
        let cc = parsed
            .iter()
            .find(|v| v["id"] == "server_cache_control_present")
            .expect("known rule present in JSON output");
        assert_eq!(cc["scope"], "server");
        assert_eq!(cc["kind"], "transaction");
        assert!(!cc["description"].as_str().unwrap_or("").is_empty());
        // Examples are always present (possibly empty); `enabled` only with --config.
        assert!(cc["examples"].is_array());
        assert!(cc.get("enabled").is_none());
        Ok(())
    }

    #[test]
    fn rules_list_json_examples_carry_compliance_and_snippet() -> anyhow::Result<()> {
        let out = rules_list(OutputFormat::Json, None)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        // At least one rule in the catalogue documents examples.
        let with_examples = parsed
            .iter()
            .find(|v| !v["examples"].as_array().unwrap().is_empty())
            .expect("some rule has examples");
        let example = &with_examples["examples"][0];
        assert!(matches!(
            example["compliance"].as_str(),
            Some("compliant") | Some("non_compliant")
        ));
        assert!(!example["snippet"].as_str().unwrap_or("").is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn rules_list_with_config_annotates_enabled() -> anyhow::Result<()> {
        // The fixture config enables exactly `server_cache_control_present`.
        let cfg_path = write_cache_control_config().await?;
        let cfg = load_validated_config(cfg_path.to_str().unwrap()).await?;

        let text = rules_list(OutputFormat::Text, Some(&cfg))?;
        let line = text
            .lines()
            .find(|l| l.starts_with("server_cache_control_present"))
            .expect("rule line present");
        assert!(line.contains(" enabled "));
        assert!(text.contains(" disabled "));

        let json = rules_list(OutputFormat::Json, Some(&cfg))?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json)?;
        let cc = parsed
            .iter()
            .find(|v| v["id"] == "server_cache_control_present")
            .expect("known rule present");
        assert_eq!(cc["enabled"], true);
        assert!(parsed.iter().any(|v| v["enabled"] == false));

        fs::remove_file(&cfg_path).await?;
        Ok(())
    }

    #[test]
    fn cli_rules_list_parses_optional_config() {
        let cli = Cli::parse_from(["lint-http", "rules", "list", "--config", "c.toml"]);
        match cli.command {
            Some(Command::Rules(args)) => match args.command {
                RulesCommand::List(a) => assert_eq!(a.config.as_deref(), Some("c.toml")),
            },
            other => panic!("expected Rules(List), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_rules_list_returns_0() -> anyhow::Result<()> {
        let cli = Cli::parse_from(["lint-http", "rules", "list"]);
        assert_eq!(dispatch(cli).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_gendocs_writes_and_returns_0() -> anyhow::Result<()> {
        let out = std::env::temp_dir().join(format!("lint_gendocs_{}", Uuid::new_v4()));
        let cli = Cli::parse_from(["lint-http", "gendocs", "--out", out.to_str().unwrap()]);
        assert_eq!(dispatch(cli).await?, 0);
        // gendocs writes the index + per-rule files under <out>/.
        assert!(out.join("rules.md").exists());
        assert!(out.join("rules").is_dir());
        let _ = fs::remove_dir_all(&out).await;
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
