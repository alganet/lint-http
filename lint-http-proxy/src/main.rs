// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

// The binary is its own compilation unit, so it includes the guard again —
// the same file, not a second copy of it. See the note in `lib.rs`.
#[cfg(test)]
#[path = "../tests/common/temp_files.rs"]
mod temp_files;

use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

use lint_http::{
    capture, client_env, config, driver, engine, lint, protocol_event_store, proxied_run, proxy,
    rules, state,
};

#[derive(Parser, Debug)]
// `long_about = None` because a flattened struct's doc comment otherwise
// becomes the binary's long description — and `GlobalArgs`'s explains *why*
// those options are global, which is a note to whoever edits this file and not
// something anyone typing `--help` asked for.
#[command(
    name = "lint-http",
    version,
    about = "HTTP-linting forward proxy",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    global: GlobalArgs,
}

/// The options that mean the same thing wherever they appear.
///
/// Four of them, and they are global because they were being redeclared per
/// command — five copies of `--config`, four of `--format` — which is four
/// chances for one of them to drift in its default or its help text, and a
/// surface where `--config` sits before the subcommand on one command and after
/// it on another. `global = true` means either position parses, so
/// `lint-http --config c.toml run -- curl` and
/// `lint-http run --config c.toml -- curl` are the same command line.
///
/// A global option is not meaningful everywhere, and that is fine: `--config`
/// says nothing to `config export`, which prints the built-in by definition.
/// What matters is that where it *is* read, it is read the same way.
#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Global options")]
struct GlobalArgs {
    /// Config TOML path. Defaults to the built-in configuration.
    #[arg(long, value_name = "PATH", global = true)]
    config: Option<String>,
    /// Output format for reports.
    #[arg(long, value_enum, global = true)]
    format: Option<OutputFormat>,
    /// Only report findings at or above this severity.
    #[arg(long, value_enum, global = true)]
    min_severity: Option<SeverityArg>,
    /// The JSONL capture file this command reads or writes: where `run`,
    /// `browse` and `proxy-start` write captures, and what `lint-captures`
    /// reads. Without it, `run` and `browse` discard theirs.
    #[arg(long, value_name = "PATH", global = true)]
    captures: Option<String>,
}

impl GlobalArgs {
    /// The report format, defaulted here rather than by clap.
    ///
    /// `Option` with the default applied at the point of use, because a
    /// `default_value_t` on a global is indistinguishable from the user typing
    /// it — and `rules list` needs to tell those apart nowhere, but `--config`
    /// next door does, so both are shaped the same way for one rule to read.
    fn format(&self) -> OutputFormat {
        self.format.unwrap_or(OutputFormat::Text)
    }

    fn min_severity(&self) -> lint::Severity {
        self.min_severity.unwrap_or(SeverityArg::Info).into()
    }

    fn captures_path(&self) -> Option<&std::path::Path> {
        self.captures.as_deref().map(std::path::Path::new)
    }
}

/// The command surface, named for how often each is reached for.
///
/// `run` is the short name because wrapping one command is the thing a person
/// does dozens of times a day; `proxy-start` is the long one because standing a
/// proxy up and configuring a client to use it is a session you begin once and
/// leave running. The names were the other way round, which had the frequent
/// case spelling out a config path and the rare case spelled `run`.
#[derive(Subcommand, Debug)]
enum Command {
    /// Run a command with its HTTP traffic proxied and linted.
    Run(RunArgs),
    /// Open a browser whose traffic is proxied and linted.
    Browse(BrowseArgs),
    /// Start the intercepting proxy and leave it listening.
    #[command(name = "proxy-start")]
    ProxyStart,
    /// Lint a recorded capture file, replaying its transactions and WebSocket
    /// sessions through the rules.
    #[command(name = "lint-captures")]
    LintCaptures(LintArgs),
    /// Inspect the rule catalogue.
    Rules(RulesArgs),
    /// Work with the configuration itself.
    Config(ConfigArgs),
}

/// `lint-http run [OPTIONS] -- <COMMAND>...`
///
/// The two severity flags compose rather than acting independently, and the
/// order is: `--min-severity` decides what the report contains, then
/// `--fail-on` reads *that report*. So `--min-severity error --fail-on info`
/// exits 0 on a warning — the warning was filtered out before anything could
/// fail on it. That is deliberate and it is `lint-captures`' rule too, whose
/// exit code likewise follows the gated set: a run must not fail on a finding
/// it declined to show, because the first thing anyone does with a failing gate
/// is look for what tripped it.
///
/// Without `--fail-on`, the wrapped command's own exit code passes through
/// untouched, which is what makes `lint-http run --` safe to leave in front of
/// a command that is being run for its own sake.
#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Print the environment a wrapped command would receive, and exit.
    #[arg(long)]
    print_env: bool,
    /// The command to run, and its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    command: Vec<String>,
    // Last, because `next_help_heading` runs from where a flattened struct is
    // declared to the end of the list — flattened first, `--print-env` and the
    // command itself would be filed under "Session options", which they are not.
    #[command(flatten)]
    session: SessionArgs,
}

/// `lint-http browse [URL]`
///
/// A browsing session against a proxy that exists only for it: a throwaway
/// profile, a CA trusted for this launch by public-key pin, and findings
/// printed as they happen. Nothing is installed and nothing is left behind.
#[derive(clap::Args, Debug)]
struct BrowseArgs {
    /// Browser executable to use. Defaults to the first Chromium-family
    /// browser found.
    #[arg(long, value_name = "PATH")]
    browser: Option<String>,
    /// Where to open. Omitted, the browser opens its own start page and
    /// whatever it fetches is still linted.
    #[arg(value_name = "URL")]
    url: Option<String>,
    // Last, for the same reason as `RunArgs`.
    #[command(flatten)]
    session: SessionArgs,
}

/// The options every session takes, whatever child it starts.
///
/// These were declared twice and diverged, in both directions: `run` could gate
/// a build on a finding and had no way to say which hosts it cared about, while
/// `browse` could scope a report to the site under test and had no way to fail
/// on anything in it. Neither gap was a decision — each flag simply got built
/// where it was first needed. Declared once, they are the same four options on
/// every command that stands a proxy up for a child, and the next one inherits
/// them rather than picking a subset.
#[derive(clap::Args, Debug, Clone, Default)]
#[command(next_help_heading = "Session options")]
struct SessionArgs {
    /// Exit non-zero when a finding *in the report* reaches this severity —
    /// findings `--min-severity` filtered out cannot trip it. Without this, the
    /// exit code is the child's.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<SeverityArg>,
    /// Report findings for this host and anything under it. Repeatable.
    /// Defaults to the host of the target, when the command knows one.
    #[arg(long, value_name = "HOST")]
    only_host: Vec<String>,
    /// Report every host, including third parties the target pulls in.
    #[arg(long, conflicts_with = "only_host")]
    all_hosts: bool,
    /// Let the child's stderr through. Off by default, so the report has stderr
    /// to itself — and because a browser writes a great deal of it, none of it
    /// about the site being linted.
    #[arg(long)]
    show_child_stderr: bool,
}

impl SessionArgs {
    /// Which hosts this session's report is about.
    ///
    /// `target` is what the session was pointed at, when the command knows —
    /// the URL a browser was opened on, or the one a driver read out of the
    /// tool's own arguments. It is the default first party, because a report
    /// about a page is about that page and not about the eleven CDNs it
    /// reaches. `run --` knows no target, so it reports everything, which is
    /// what it always did.
    fn scope(&self, target: Option<&str>) -> HostScope {
        if self.all_hosts {
            return HostScope::all();
        }
        if !self.only_host.is_empty() {
            return HostScope::new(self.only_host.clone());
        }
        // Narrowing to nothing would report nothing, so a target this cannot
        // read widens rather than narrows.
        match target.and_then(uri_host) {
            Some(host) => HostScope::new([host.to_string()]),
            None => HostScope::all(),
        }
    }
}

#[derive(clap::Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Print the built-in configuration, ready to edit and pass to `--config`.
    Export,
}

/// `lint-http lint-captures [CAPTURES]`
///
/// The file may be named as the positional or as the global `--captures`, which
/// is the same file under the same name it takes everywhere else — what `run`
/// and `browse` write is what this reads. Naming it twice is an error rather
/// than a precedence rule nobody would remember.
#[derive(clap::Args, Debug)]
struct LintArgs {
    /// JSONL capture file to lint. May also be given as `--captures`.
    #[arg(value_name = "CAPTURES")]
    capture_file: Option<String>,
}

impl LintArgs {
    /// The capture file to read, from whichever spelling was used.
    fn path(&self, global: &GlobalArgs) -> anyhow::Result<String> {
        match (self.capture_file.as_deref(), global.captures.as_deref()) {
            (Some(positional), None) => Ok(positional.to_string()),
            (None, Some(flag)) => Ok(flag.to_string()),
            (Some(_), Some(_)) => {
                anyhow::bail!(
                    "the capture file was given twice; drop one of the positional or --captures"
                )
            }
            (None, None) => {
                anyhow::bail!("no capture file given; try `lint-http lint-captures captures.jsonl`")
            }
        }
    }
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
    /// List every rule and its metadata. With `--config`, each rule is
    /// annotated with whether that config enables it.
    List,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// Send `warn!` and friends to stderr, once per process.
///
/// Every command that stands a proxy up needs this, and for a long time only
/// one of them called it: the initializer lived in `load_and_prepare`, which is
/// the `proxy-start` path, back when `run` *was* `proxy-start`. After the
/// rename `run` and `browse` ran a proxy through a different function and
/// silently discarded every diagnostic it produced.
///
/// **That combination is the one that makes this tool lie.** `run` and `browse`
/// also discard the child's stderr by default, so a session where interception
/// never worked — TLS disabled in the config, a CA that could not be written, a
/// proxy task that failed before it accepted a connection — printed
/// `0 violation(s) in 0 transaction(s)` and nothing else. A clean report and a
/// broken run were indistinguishable.
///
/// `try_init` rather than `init`: it is called from every dispatch arm and from
/// tests that may already have a subscriber, and a second initialization is a
/// no-op rather than a panic. `RUST_LOG` still selects the level.
fn init_diagnostics() {
    use std::io::IsTerminal;
    // **To stderr, explicitly.** `fmt`'s default writer is *stdout*, which for
    // `run` and `browse` belongs to the wrapped command — so the default would
    // interleave log lines with a response body and break the one contract
    // these commands document: `run -- curl url > body.html 2> report.txt`
    // writes only the body. The report already goes to stderr; diagnostics
    // about the same run belong on the same stream.
    //
    // ANSI only when stderr is a terminal, or the escapes end up in whatever
    // file a redirect pointed at.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .try_init();
}

/// Load the config and validate every enabled rule's section, failing fast on a
/// malformed config. Shared by every subcommand.
async fn load_validated_config(
    config_path: Option<&str>,
) -> anyhow::Result<std::sync::Arc<config::Config>> {
    let cfg = config::Config::load_or_builtin(config_path).await?;
    rules::validate_rules(&cfg)?;
    Ok(std::sync::Arc::new(cfg))
}

/// Load + validate the config and build the proxy's runtime inputs.
///
/// Proxy-specific: it builds a `CaptureWriter`. Takes the config *path* rather
/// than the parsed CLI struct, so the proxy entry points are decoupled from the
/// command surface.
async fn load_and_prepare(
    config_path: Option<&str>,
    captures_override: Option<&str>,
) -> anyhow::Result<(
    SocketAddr,
    capture::CaptureWriter,
    std::sync::Arc<config::Config>,
)> {
    let mut cfg = load_validated_config(config_path).await?;

    // `--captures` names the file this command writes, which for the proxy is
    // the one the config already names — so the flag overrides it rather than
    // being inert here.
    if let Some(path) = captures_override {
        std::sync::Arc::make_mut(&mut cfg).general.captures = path.to_string();
    }

    let addr: SocketAddr = cfg.general.listen.parse()?;
    let capture_writer = capture::CaptureWriter::new(
        cfg.general.captures.clone(),
        cfg.general.captures_include_body,
    )
    .await?;

    Ok((addr, capture_writer, cfg))
}

/// Run the proxy until Ctrl-C / shutdown.
async fn run_app(config_path: Option<&str>, captures: Option<&str>) -> anyhow::Result<()> {
    let (addr, capture_writer, cfg) = load_and_prepare(config_path, captures).await?;
    // `run_proxy` wires Ctrl-C to a graceful shutdown.
    proxy::run_proxy(addr, capture_writer, cfg).await
}

// Testable variant of run_app that allows tests to pass in an accept limit so the
// proxy returns after a bounded number of connections.
#[cfg(test)]
async fn run_app_with_limit(
    config_path: Option<&str>,
    accept_limit: Option<usize>,
) -> anyhow::Result<()> {
    let (addr, capture_writer, cfg) = load_and_prepare(config_path, None).await?;
    crate::proxy::run_proxy_with_limit(addr, capture_writer, cfg, accept_limit).await
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

/// The stderr twin of [`write_stdout`], for the one report that must not land
/// on stdout: `run` gives stdout to the command it wraps, so a report printed
/// there would interleave with — and corrupt — whatever the user is piping.
fn write_stderr(s: &str) -> anyhow::Result<()> {
    use std::io::Write;
    match std::io::stderr().write_all(s.as_bytes()) {
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
    specifications: &'static [rules::SpecRef],
    examples: &'static [rules::Example],
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
}

/// Collect every transaction rule then every protocol rule, each already
/// id-sorted by its `LazyLock` view. `cfg` (from `--config`) fills `enabled`.
///
/// Only `kind` and `scope` distinguish the two halves; everything else is
/// [`rules::RuleMeta`], which both traits carry, so each iterator pairs a rule
/// with the two labels its trait decides and the `RuleInfo` literal is written
/// once. Protocol rules are labelled `"protocol"` for both, having no scope to
/// report.
fn collect_rule_info(cfg: Option<&config::Config>) -> Vec<RuleInfo> {
    let transaction = rules::RULES.iter().map(|r| {
        (
            *r as &dyn rules::RuleMeta,
            "transaction",
            scope_label(r.scope()),
        )
    });
    let protocol = rules::PROTOCOL_RULES
        .iter()
        .map(|r| (*r as &dyn rules::RuleMeta, "protocol", "protocol"));
    transaction
        .chain(protocol)
        .map(|(rule, kind, scope)| RuleInfo {
            id: rule.id(),
            kind,
            scope,
            title: rule.title(),
            description: rule.description(),
            specifications: rule.specifications(),
            examples: rule.examples(),
            enabled: cfg.map(|c| c.is_enabled(rule.id())),
        })
        .collect()
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

/// Lint a recorded capture file by replaying its records through the rule
/// engine, printing violations to stdout. Returns the number of violations found
/// so the caller can map it to an exit code.
///
/// The replay mirrors the live proxy pipeline: each transaction is linted against
/// the history of prior transactions, then recorded — so stateful rules see the
/// same history they would live. WebSocket session records are replayed
/// per-message through the protocol rules (rebuilding the frame events the live
/// relay emits); their live-recorded `violations` field is ignored — replay
/// re-lints from the message metadata under the *current* config. The stores'
/// TTLs never evict here (the read paths apply no age filter and cleanup is
/// never called), so the whole file is visible regardless of record age.
async fn lint_app(
    config_path: Option<&str>,
    captures_path: &str,
    format: OutputFormat,
    min_severity: lint::Severity,
) -> anyhow::Result<usize> {
    let cfg = load_validated_config(config_path).await?;
    // `load_capture_records` tolerates a missing file (it backs the proxy's
    // optional cold-start seeding). For an explicit `lint-captures <file>` a
    // missing path is a user error — fail loudly rather than letting CI pass
    // green on a typo'd path.
    if !tokio::fs::try_exists(captures_path).await.unwrap_or(false) {
        anyhow::bail!("capture file not found: {captures_path}");
    }
    let records = capture::load_capture_records(captures_path).await?;
    let report = lint_records(&cfg, records, min_severity)?;
    let total = report.total();
    write_stdout(&render_lint_report(
        &report.findings,
        report.transaction_count,
        report.websocket_count,
        format,
    )?)?;
    Ok(total)
}

/// The findings of one replay, with the counts the summary line needs.
struct LintReport {
    findings: Vec<FindingsBlock>,
    transaction_count: usize,
    websocket_count: usize,
}

impl LintReport {
    fn total(&self) -> usize {
        self.findings.iter().map(|f| f.violations().len()).sum()
    }
}

/// One record's recorded findings, gated by severity — `None` when nothing
/// survives the gate.
///
/// **The single place a capture record becomes a report block.** `browse`
/// printed its live lines from one copy of this logic and counted its summary
/// from a replay, and the two disagreed: blocks scrolled past that the number
/// at the bottom did not include. Two callers, one function, and the tally can
/// no longer describe a different set of findings than the reader saw.
fn gated_block(
    record: &capture::CaptureRecord,
    min_severity: lint::Severity,
) -> Option<FindingsBlock> {
    let gate = |violations: &[lint::Violation]| -> Vec<lint::Violation> {
        violations
            .iter()
            .filter(|v| v.severity >= min_severity)
            .cloned()
            .collect()
    };
    match record {
        capture::CaptureRecord::HttpTransaction(tx) => {
            let violations = gate(&tx.violations);
            if violations.is_empty() {
                return None;
            }
            Some(FindingsBlock::HttpTransaction(TransactionFindings {
                method: tx.request.method.clone(),
                uri: tx.request.uri.clone(),
                status: tx.response.as_ref().map(|r| r.status),
                violations,
            }))
        }
        capture::CaptureRecord::WebsocketSession(session) => {
            let violations = gate(&session.violations);
            if violations.is_empty() {
                return None;
            }
            Some(FindingsBlock::WebsocketSession(WebsocketFindings {
                session_id: session.id,
                transaction_id: session.transaction_id,
                close_code: session.close_code,
                violations,
            }))
        }
    }
}

/// The findings a driven session's own proxy already made.
///
/// `run` and `browse` do not re-lint what they just watched. The proxy ran the
/// enabled rules over each transaction as it committed, with the bodies in
/// hand, and wrote the result into the record; this reads it back.
///
/// **Replaying instead is how this tool reported a malformed body as clean.**
/// `HttpTransaction::request_body` and `response_body` are `#[serde(skip)]`, so
/// no body survives the capture file — and the seven rules that read one could
/// therefore never fire in a `run` report, however loudly the live pass had
/// found them. `lint-http run --fail-on error -- curl https://api/thing`
/// returned a green gate for an `application/problem+json` document the proxy
/// had already rejected.
///
/// Nothing is given up by trusting the record. `Violation` serializes whole —
/// severity, defect id and specification citation included — so what comes back
/// is the finding exactly as the live pass made it, under the configuration
/// that pass ran with. And that configuration is by construction the one this
/// command was handed: the session started the proxy with it moments ago. It is
/// also cheaper, since nothing is parsed or linted twice.
///
/// [`lint_records`] stays for `lint-captures`, whose config genuinely can
/// differ from the one that wrote the file.
fn recorded_findings(
    records: &[capture::CaptureRecord],
    min_severity: lint::Severity,
) -> LintReport {
    let mut findings = Vec::new();
    let mut tx_count = 0usize;
    let mut ws_count = 0usize;
    for record in records {
        match record {
            capture::CaptureRecord::HttpTransaction(_) => tx_count += 1,
            capture::CaptureRecord::WebsocketSession(_) => ws_count += 1,
        }
        findings.extend(gated_block(record, min_severity));
    }
    LintReport {
        findings,
        transaction_count: tx_count,
        websocket_count: ws_count,
    }
}

/// Replay records through the rules — what `lint-captures` does.
///
/// **This is no longer how `run` and `browse` report,** and the sentence that
/// stood here said it was: that they were `lint-captures` pointed at a file the
/// run had just produced, so no report could drift. True, and it was the
/// defect — a replay re-asks the rules from a record, a record carries no body,
/// and the answer came back clean. Those commands read the finding off the
/// record now, in [`recorded_findings`], and this is left to the one caller
/// whose configuration can genuinely differ from the one that wrote the file.
///
/// Where a replay and a live pass disagree, **the live pass is canonical**. It
/// saw the bodies, it saw whatever `general.captures_seed` had seeded the state
/// with, and it saw the transactions in the order they actually arrived; this
/// rebuilds a history from the file alone and can match none of the three.
fn lint_records(
    cfg: &config::Config,
    records: Vec<capture::CaptureRecord>,
    min_severity: lint::Severity,
) -> anyhow::Result<LintReport> {
    let state = state::StateStore::new(cfg.general.ttl_seconds, cfg.general.max_history);
    // Precompute the enabled rule set once, then reuse it across the replay.
    let engine = engine::PreparedEngine::new(cfg)?;

    let mut findings = Vec::new();
    let mut tx_count = 0usize;
    let mut ws_count = 0usize;
    for record in records {
        match record {
            capture::CaptureRecord::HttpTransaction(tx) => {
                tx_count += 1;
                let mut violations = engine.lint_transaction(&tx, &state);
                // Record *before* gating: stateful rules must see every
                // transaction in the file regardless of what the report includes.
                state.record_transaction(&tx);
                violations.retain(|v| v.severity >= min_severity);
                if violations.is_empty() {
                    continue;
                }
                // The record is owned, so the report fields move out of it.
                findings.push(FindingsBlock::HttpTransaction(TransactionFindings {
                    status: tx.response.as_ref().map(|r| r.status),
                    method: tx.request.method,
                    uri: tx.request.uri,
                    violations,
                }));
            }
            capture::CaptureRecord::WebsocketSession(session) => {
                ws_count += 1;
                let mut violations = lint_websocket_session(&session, cfg, &engine);
                violations.retain(|v| v.severity >= min_severity);
                if violations.is_empty() {
                    continue;
                }
                findings.push(FindingsBlock::WebsocketSession(WebsocketFindings {
                    session_id: session.id,
                    transaction_id: session.transaction_id,
                    close_code: session.close_code,
                    violations,
                }));
            }
        }
    }

    Ok(LintReport {
        findings,
        transaction_count: tx_count,
        websocket_count: ws_count,
    })
}

/// Replay one captured WebSocket session through the protocol rules, mirroring
/// the live relay: each message becomes the frame event the relay would have
/// built (via the shared [`WebSocketMessageInfo::frame_event`] mapping, stamped
/// with the session timestamp since per-message times aren't captured), is
/// linted against the session's prior events, then recorded.
///
/// Each session gets a **fresh** event store bounded by the same
/// `max_protocol_event_history` the live pipeline uses, so replay eviction
/// mirrors live eviction and a session record appearing twice in one capture
/// (e.g. concatenated files) can't contaminate its second replay with the
/// first's history. The captured session has no connection id, so the session
/// id stands in as the history key — live grouping is per connection, but the
/// WebSocket sequence rules already filter history by `session_id`, so the
/// narrower key changes nothing for them.
fn lint_websocket_session(
    session: &lint_http::websocket_session::WebSocketSession,
    cfg: &config::Config,
    engine: &engine::PreparedEngine,
) -> Vec<lint::Violation> {
    let event_store = protocol_event_store::ProtocolEventStore::new(
        cfg.general.ttl_seconds,
        cfg.general.max_protocol_event_history,
    );
    let mut violations = Vec::new();
    for msg in &session.messages {
        // Frames recorded with their own arrival time replay with it; records
        // written before the per-frame field existed fall back to the session
        // timestamp, which is all they ever carried.
        let event = msg.frame_event(
            msg.timestamp.unwrap_or(session.timestamp),
            session.id,
            session.id,
            &session.extensions,
        );
        violations.extend(engine.lint_protocol_event(&event, &event_store));
        event_store.record_event(&event);
    }
    violations
}

/// One capture record's surviving findings, tagged by record kind in the JSON
/// output (`"kind": "http_transaction" | "websocket_session"`).
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FindingsBlock {
    HttpTransaction(TransactionFindings),
    WebsocketSession(WebsocketFindings),
}

impl FindingsBlock {
    fn violations(&self) -> &[lint::Violation] {
        match self {
            FindingsBlock::HttpTransaction(f) => &f.violations,
            FindingsBlock::WebsocketSession(f) => &f.violations,
        }
    }
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

/// One replayed WebSocket session's surviving findings (`close_code` is `null`
/// when the session ended without a Close frame).
#[derive(serde::Serialize)]
struct WebsocketFindings {
    session_id: uuid::Uuid,
    transaction_id: uuid::Uuid,
    close_code: Option<u16>,
    violations: Vec<lint::Violation>,
}

/// Which hosts a report is about.
///
/// **`browse` is unusable without this.** One real page pulls in tens of
/// origins nobody in the room controls, and with the whole catalogue enabled
/// the result is a wall of findings about somebody else's CDN — true, and not
/// actionable, and enough of it to bury the findings that are. So a session
/// opened on a URL reports that URL's host by default and counts the rest.
///
/// Empty means every host, which is what `--all-hosts` selects and what a
/// session opened on no URL falls back to, there being no first party to infer.
#[derive(Debug, Clone, Default)]
struct HostScope {
    hosts: Vec<String>,
}

impl HostScope {
    fn all() -> Self {
        Self::default()
    }

    fn is_all(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Does this report include the given request target?
    ///
    /// A scope matches its own host and anything under it, so `example.com`
    /// covers `www.example.com` and `api.example.com` — a site is rarely one
    /// name, and a default that reported only the exact host typed would drop
    /// the API calls the page makes, which are usually the interesting half.
    /// The dot is what keeps it from also covering `notexample.com`.
    /// Build a scope, normalizing what the user typed.
    ///
    /// A port is stripped, because `uri_host` strips it from the target too:
    /// `--only-host localhost:3000` compared whole against `localhost` matches
    /// nothing, which scopes away the entire session and reports a clean
    /// nothing — the exact failure `--proxy-bypass-list=<-loopback>` exists to
    /// prevent, arriving one flag later. Lowercased once here rather than per
    /// comparison, since the list is fixed for the session.
    fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            hosts: hosts
                .into_iter()
                .map(|host| {
                    let host = host.to_ascii_lowercase();
                    uri_host(&host).map_or(host.clone(), str::to_string)
                })
                .collect(),
        }
    }

    fn includes(&self, uri: &str) -> bool {
        if self.is_all() {
            return true;
        }
        let Some(host) = uri_host(uri) else {
            // A target with no host to compare — an origin-form request the
            // capture recorded as a path. Kept: the alternative is dropping a
            // finding for a reason the user cannot see.
            return true;
        };
        // `strip_suffix` rather than a byte offset computed from the scope's
        // length: that offset indexes a string this does not control, and an
        // internationalized host would land it mid-character and panic. The
        // remainder is empty for an exact match and ends in a dot for a
        // subdomain, which is the whole predicate — and it allocates nothing,
        // which matters because this runs three times per record.
        self.hosts.iter().any(|scope| {
            host.len() == scope.len() && host.eq_ignore_ascii_case(scope)
                || host
                    .get(..host.len().saturating_sub(scope.len()))
                    .zip(host.get(host.len().saturating_sub(scope.len())..))
                    .is_some_and(|(prefix, tail)| {
                        prefix.ends_with('.') && tail.eq_ignore_ascii_case(scope)
                    })
        })
    }

    /// Does this scope keep the given block?
    ///
    /// One predicate for the lines `browse` prints as they happen and for the
    /// split it makes at the end, so a finding cannot be shown by one and
    /// counted as somebody else's by the other.
    ///
    /// A WebSocket session is always kept: it exists because an upgrade was made
    /// deliberately, and its record carries no target to compare anyway.
    fn keeps(&self, block: &FindingsBlock) -> bool {
        match block {
            FindingsBlock::HttpTransaction(f) => self.includes(&f.uri),
            FindingsBlock::WebsocketSession(_) => true,
        }
    }

    /// Split a report in two: what this scope includes, and how many findings
    /// it left out.
    ///
    /// The count is of *findings*, not transactions, because that is the number
    /// the summary compares against — "12 shown, 340 elsewhere" answers "is the
    /// default hiding something I want" and a transaction count does not.
    fn apply(&self, findings: Vec<FindingsBlock>) -> (Vec<FindingsBlock>, usize) {
        if self.is_all() {
            return (findings, 0);
        }
        let mut kept = Vec::new();
        let mut elsewhere = 0;
        for block in findings {
            if self.keeps(&block) {
                kept.push(block);
            } else {
                elsewhere += block.violations().len();
            }
        }
        (kept, elsewhere)
    }
}

/// The host out of a request target, for scope comparison only.
///
/// Deliberately lax where the rule helpers are strict: those transcribe a
/// grammar and refuse what does not match it, which is right for a rule and
/// wrong here — a target this cannot read should widen the report, not narrow
/// it. Handles the two shapes a capture holds, an absolute URI and an
/// authority-form target, and the bracketed IPv6 literal in either.
fn uri_host(uri: &str) -> Option<&str> {
    // The `://` has to come before the path, or a target that merely *carries*
    // a URL — `/oauth/callback?redirect_uri=https://cdn.other.net/x` — is read
    // as being addressed to that host. Under a scope that would silently drop a
    // first-party finding because of a third party named in its query string.
    let scheme_end = uri.find("://").filter(|end| {
        uri[..*end]
            .find(['/', '?', '#'])
            .is_none_or(|delim| delim > *end)
    });
    let after_scheme = match scheme_end {
        Some(end) => &uri[end + 3..],
        None => uri,
    };
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8080` — the colons inside the brackets are the address.
        return rest.split_once(']').map(|(host, _)| host);
    }
    let host = authority.split(':').next()?;
    (!host.is_empty()).then_some(host)
}

/// One record's findings, as the text report prints them.
///
/// Extracted from [`render_lint_report`] so `browse` can print a block the
/// moment its transaction commits. A browsing session runs for minutes and
/// makes hundreds of requests; saving every finding for the end would be the
/// same output delivered when it is no longer about anything on screen. Same
/// function, so the live lines and a replayed report cannot disagree on shape.
fn render_findings_block(block: &FindingsBlock) -> anyhow::Result<String> {
    use std::fmt::Write;
    let mut out = String::new();
    match block {
        FindingsBlock::HttpTransaction(f) => {
            let status = f
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(out, "{} {} -> {}", f.method, f.uri, status)?;
        }
        FindingsBlock::WebsocketSession(f) => {
            let close = f
                .close_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(
                out,
                "websocket session {} (upgrade {}) -> close {}",
                f.session_id, f.transaction_id, close
            )?;
        }
    }
    for v in block.violations() {
        // Both names, when the finding carries both: the rule is what ran, the
        // defect is what it found, and they are tuned by two different sections
        // of the configuration. `rule/defect` rather than either alone —
        // dropping the rule would hide which analysis to switch off, and
        // dropping the defect would hide the name `[violations.*]` takes. A
        // finding from a rule that names no defect prints exactly as it always
        // has.
        let name = if v.violation.is_empty() {
            v.rule.clone()
        } else {
            format!("{}/{}", v.rule, v.violation)
        };
        write!(out, "  {:<5} {}  {}", v.severity.name(), name, v.message)?;
        // The specification text the finding enforces, when the rule attached
        // one at the violation site.
        if let Some(cite) = &v.cite {
            write!(out, "  [{cite}]")?;
        }
        writeln!(out)?;
    }
    Ok(out)
}

/// Render the `lint-captures` report: the text form ends with a human summary line
/// (whose violation count is derived from `findings`, so it can't disagree
/// with the blocks above it); the JSON form is a bare array of
/// [`FindingsBlock`]s so it stays machine-parseable. The summary mentions
/// websocket sessions only when the capture had any, so pure-HTTP output is
/// unchanged.
fn render_lint_report(
    findings: &[FindingsBlock],
    transaction_count: usize,
    websocket_count: usize,
    format: OutputFormat,
) -> anyhow::Result<String> {
    match format {
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(findings)?)),
        OutputFormat::Text => {
            let mut out = String::new();
            for block in findings {
                out.push_str(&render_findings_block(block)?);
            }
            let total: usize = findings.iter().map(|f| f.violations().len()).sum();
            out.push_str(&render_summary(total, transaction_count, websocket_count));
            Ok(out)
        }
    }
}

/// The line a text report ends with.
///
/// Its own function because a session that printed its findings as they
/// happened has nothing left to print *but* this, and a second copy of the
/// sentence is a second thing to keep in step with the first. It was two
/// copies, and the one `browse` used had already grown a websocket clause the
/// other spelled differently.
fn render_summary(total: usize, transaction_count: usize, websocket_count: usize) -> String {
    use std::fmt::Write;
    let mut out = format!("\n{total} violation(s) in {transaction_count} transaction(s)");
    if websocket_count > 0 {
        let _ = write!(out, " and {websocket_count} websocket session(s)");
    }
    out.push('\n');
    out
}

/// How a session hands its report over — the one thing a wrapped command and a
/// browsing session do not agree about.
#[derive(Debug, Clone, Copy)]
struct ReportStyle {
    /// Print each finding as its transaction commits, leaving the end of the
    /// session with only the tally to print.
    ///
    /// A session someone sits in front of for minutes needs this: holding
    /// everything until the window closes delivers the report after the thing
    /// it describes is gone. A wrapped command that finishes in a second does
    /// not, and streaming would only interleave findings with the tool's own
    /// output. Text only — `--format json` is one document by definition.
    live: bool,
    /// Whether a `--format json` document goes to stdout.
    ///
    /// `run` says no, and must: stdout belongs to the wrapped command, so a
    /// report written there would corrupt the body someone is redirecting. A
    /// browsing session says yes — a browser has no stdout worth protecting,
    /// and `browse --format json > findings.json` is what the documentation has
    /// promised since the command existed. The *text* report is on stderr
    /// either way, and so is every diagnostic.
    json_to_stdout: bool,
}

/// Print one session's report, and hand back the findings a gate would read.
///
/// The whole tail of a session: gate by severity, divide by scope, print in the
/// requested format, and say what the scope left out. `run` and `browse` each
/// had their own copy, which is why only one of them counted transactions the
/// way its own summary line claimed to.
fn report_session(
    records: &[capture::CaptureRecord],
    scope: &HostScope,
    global: &GlobalArgs,
    style: ReportStyle,
) -> anyhow::Result<Vec<FindingsBlock>> {
    let report = recorded_findings(records, global.min_severity());

    // The summary has to divide like with like: a scoped violation count over
    // an unscoped transaction count reads as "3 violation(s) in 480
    // transaction(s)" when 472 of those were never in the report's scope at all.
    let in_scope_transactions = records
        .iter()
        .filter(|record| match record {
            capture::CaptureRecord::HttpTransaction(tx) => scope.includes(&tx.request.uri),
            capture::CaptureRecord::WebsocketSession(_) => false,
        })
        .count();

    let (findings, elsewhere) = scope.apply(report.findings);
    let total: usize = findings.iter().map(|f| f.violations().len()).sum();

    match global.format() {
        OutputFormat::Json => {
            let document = render_lint_report(
                &findings,
                in_scope_transactions,
                report.websocket_count,
                OutputFormat::Json,
            )?;
            if style.json_to_stdout {
                write_stdout(&document)?;
            } else {
                write_stderr(&document)?;
            }
            // The document is scoped and nothing inside it says so — it is an
            // array, and giving it a wrapper would fork the shape
            // `lint-captures --format json` produces. The note goes to stderr,
            // which JSON mode leaves free, so a reader can tell a clean session
            // from one whose findings were filtered.
            if elsewhere > 0 {
                write_stderr(&format!(
                    "note: {elsewhere} violation(s) on other hosts are not in this document (--all-hosts)\n"
                ))?;
            }
        }
        OutputFormat::Text => {
            let mut out = String::new();
            // A live session already printed the blocks; only the tally is new.
            if !style.live {
                for block in &findings {
                    out.push_str(&render_findings_block(block)?);
                }
            }
            out.push_str(&render_summary(
                total,
                in_scope_transactions,
                report.websocket_count,
            ));
            if elsewhere > 0 {
                // Said rather than silently dropped: a reader has to be able to
                // tell "clean" from "scoped away from the mess". The other
                // transaction count goes with it, so both halves of the session
                // are accounted for.
                let others = report
                    .transaction_count
                    .saturating_sub(in_scope_transactions);
                out.push_str(&format!(
                    "{elsewhere} more violation(s) in {others} transaction(s) on other hosts, not shown (--all-hosts)\n"
                ));
            }
            write_stderr(&out)?;
        }
    }
    Ok(findings)
}

/// The code a session exits with.
///
/// The child's, unless `--fail-on` says otherwise — so putting `lint-http` in
/// front of a command does not change what that command's success means. A
/// child that already failed keeps its own code even when findings would also
/// have tripped the gate, because its code is the more specific answer. And a
/// clean lint never overrides a failure: a passing test suite that happens to
/// be tidy still exits 0, a failing one still exits non-zero whatever the
/// findings said.
///
/// `unwrap_or(1)` on the conversion: a code that does not fit in a `u8` is an
/// abnormal exit — a Windows crash code, say — and rounding that to *success*
/// would report green on a child that died before doing anything.
fn session_exit(child_code: i32, fail_on: Option<SeverityArg>, findings: &[FindingsBlock]) -> u8 {
    if child_code != 0 {
        return u8::try_from(child_code).unwrap_or(1);
    }
    let Some(fail_on) = fail_on else {
        return 0;
    };
    let fail_on: lint::Severity = fail_on.into();
    let tripped = findings
        .iter()
        .flat_map(FindingsBlock::violations)
        .any(|v| v.severity >= fail_on);
    u8::from(tripped)
}

/// Wrap one command: stand a proxy up for it, run it, report what crossed.
///
/// The exit code is the child's unless `--fail-on` says otherwise, so putting
/// `lint-http run --` in front of a command does not change what that command's
/// success means. The report goes to stderr because stdout belongs to the child.
async fn run_wrapped(args: RunArgs, global: &GlobalArgs) -> anyhow::Result<u8> {
    let cfg = load_validated_config(global.config.as_deref()).await?;

    // `--print-env` answers "what would this do to my environment" without
    // doing it, so it needs no child and reports against a placeholder address.
    if args.print_env {
        write_stdout(&render_env_preview())?;
        return Ok(0);
    }

    let Some((program, rest)) = args.command.split_first() else {
        anyhow::bail!("no command given; try `lint-http run -- curl https://example.com`");
    };
    // `trailing_var_arg` + `allow_hyphen_values` is what lets the wrapped
    // command keep its own flags, and it means clap cannot reject a mistyped
    // one of ours: `--fail-onn error` parses as a *program* named `--fail-onn`.
    // Caught here rather than by the OS, which would report it as a missing
    // file — after a proxy and a CA had already been stood up for it.
    if program.starts_with('-') {
        anyhow::bail!(
            "`{program}` is not a command. Options for lint-http go before `--`; \
             everything after it is the command to run — `lint-http run [OPTIONS] -- {program} ...`"
        );
    }

    let run = proxied_run::run_proxied(
        (*cfg).clone(),
        program,
        rest,
        global.captures_path(),
        args.session.show_child_stderr,
    )
    .await?;

    // No target: `run --` is tool-blind by design and cannot know what the
    // command it wrapped was aimed at, so without `--only-host` it reports
    // every origin the child reached.
    let scope = args.session.scope(None);
    let findings = report_session(
        &run.records,
        &scope,
        global,
        ReportStyle {
            live: false,
            json_to_stdout: false,
        },
    )?;
    Ok(session_exit(
        run.exit_code.unwrap_or(1),
        args.session.fail_on,
        &findings,
    ))
}

/// The environment `run` would add, rendered for a human.
///
/// The address and path are placeholders — every real run picks a fresh port
/// and a fresh temporary CA — so this answers *which* variables are set and
/// who reads them, which is the question someone debugging an unwrapped client
/// is actually asking.
fn render_env_preview() -> String {
    use std::fmt::Write;

    // Built by the same function a real run calls, against placeholder inputs,
    // so the preview cannot describe an environment the run does not set. It
    // used to render the values itself and named `ca.crt` where a run passes
    // the *trust bundle* — which is not a cosmetic difference: the bare CA
    // replaces a client's trust instead of extending it, so anyone reproducing
    // a run by hand from this output broke every connection the proxy was not
    // intercepting.
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("a literal address parses");
    let placeholder = std::path::PathBuf::from("<tmp>/trust-bundle.crt");
    let env = client_env::client_env(addr, Some(&placeholder));
    let reads: std::collections::HashMap<&str, &str> = client_env::CLIENT_ENV
        .iter()
        .map(|var| (var.name, var.reads))
        .collect();

    let mut out = String::new();
    out.push_str("# Set for the wrapped command. The port and CA path are per-run.\n");
    for (name, value) in env {
        // The address is a placeholder; show the port as one too.
        let value = value.replace("127.0.0.1:0", "127.0.0.1:<port>");
        let _ = writeln!(
            out,
            "{:<20} {:<28} # {}",
            name,
            value,
            reads.get(name).copied().unwrap_or_default()
        );
    }
    out
}

/// Open a browser against a session proxy and report what it fetches.
///
/// Everything below the first three lines is [`drive`], because a browsing
/// session is one tool driven through a session of its own and there is nothing
/// about it that only a browser does.
async fn browse(args: BrowseArgs, global: &GlobalArgs) -> anyhow::Result<u8> {
    let BrowseArgs {
        browser,
        url,
        session,
    } = args;
    let chromium: &'static dyn driver::Driver = &driver::chromium::Chromium;
    let tool = chromium.locate(browser.as_deref())?;
    let invocation = chromium.inspect(&url.into_iter().collect::<Vec<_>>());
    drive(chromium, tool, invocation, &session, global).await
}

/// Run one tool through a session of its own, configured the way that tool
/// documents.
///
/// Every step here is the same whatever the tool is, and the handful that are
/// not are the driver's four answers: where its executable is, what its
/// arguments asked for, how to write the session onto its command line, and
/// whether anyone is sitting in front of it. Adding a tool is a
/// [`driver::Driver`] and an entry in [`driver::DRIVERS`], not another command
/// shaped like this one.
async fn drive(
    driver: &'static dyn driver::Driver,
    tool: driver::Tool,
    invocation: driver::Invocation,
    session_args: &SessionArgs,
    global: &GlobalArgs,
) -> anyhow::Result<u8> {
    let mut cfg = load_validated_config(global.config.as_deref()).await?;

    // **Before a proxy is stood up.** The failure this whole seam exists to
    // catch is a clean report rather than an error, and an invocation that has
    // already disabled certificate verification produces exactly that — so it
    // is said while there is still a decision to make, not afterwards.
    raise(&invocation.objections)?;

    // An invocation that sends a body is the reason to capture one: the rules
    // that read a body are the ones a `-d @order.json` was about, and they see
    // nothing unless the proxy kept the octets.
    if invocation.sends_body {
        std::sync::Arc::make_mut(&mut cfg)
            .general
            .captures_include_body = true;
    }

    // The scope, decided before anything opens so it can be reported. The first
    // party is whatever the invocation was aimed at; with no target there is
    // none to infer.
    let scope = session_args.scope(invocation.target.as_deref());

    let session = proxied_run::ProxySession::start((*cfg).clone(), global.captures_path()).await?;
    let pin = session.spki_pin().await?;
    let scratch = session.scratch("driver");
    std::fs::create_dir_all(&scratch)?;

    let launch = driver.command(
        &tool,
        &invocation,
        &driver::Target {
            addr: session.addr,
            trust_bundle: session.trust_bundle.as_deref(),
            spki_pin: pin.as_deref(),
            scratch: &scratch,
        },
    )?;
    raise(&launch.objections)?;

    write_stderr(&format!(
        "{} through 127.0.0.1:{}{}\n",
        tool.name,
        session.addr.port(),
        match &scope.hosts[..] {
            [] => " — reporting every host".to_string(),
            hosts => format!(" — reporting {}", hosts.join(", ")),
        }
    ))?;

    // A session someone sits in front of narrates; JSON mode stays silent so
    // its one document is the only thing on the stream a machine is reading.
    let streaming = driver.interactive() && matches!(global.format(), OutputFormat::Text);
    let live = streaming.then(|| {
        tokio::spawn(live_reporter(
            session.subscribe(),
            scope.clone(),
            global.min_severity(),
        ))
    });

    // A failure to launch is still an error and propagates; an interrupt is not,
    // because ending a session with Ctrl-C is how an interactive one ordinarily
    // ends. Distinguishing them is why `await_child` returns a `ChildOutcome`.
    let outcome =
        proxied_run::await_child(spawn_driven(launch.command, session_args.show_child_stderr))
            .await?;

    // Drained *before* the live reporter is stopped, so the last transactions —
    // the ones committed while the window was closing — are printed rather than
    // only counted. Stopping it first would leave a summary that names findings
    // the reader never saw scroll past.
    let records = session.finish().await?;
    if let Some(live) = live {
        // Finishing the session drops the capture writer, which closes the feed
        // the reporter is reading — so it drains what is buffered and returns on
        // its own. Awaiting that is what actually gets the last lines out;
        // aborting here would race the very transactions the summary counts.
        // Bounded so a reporter that somehow cannot finish does not hold the
        // command open.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), live).await;
    }
    let exit = match outcome {
        proxied_run::ChildOutcome::Exited(status) => status.code().unwrap_or(0),
        proxied_run::ChildOutcome::Interrupted => 0,
    };

    let findings = report_session(
        &records,
        &scope,
        global,
        ReportStyle {
            // A streaming session already printed the blocks as they committed.
            live: streaming,
            json_to_stdout: driver.json_to_stdout(),
        },
    )?;
    Ok(session_exit(exit, session_args.fail_on, &findings))
}

/// Say what a driver objected to, and stop if it refused.
///
/// Warnings first and all of them, then the refusal — a user who has typed two
/// things that spoil a session should be told about both rather than about
/// whichever one this happened to check first.
fn raise(objections: &[driver::Objection]) -> anyhow::Result<()> {
    for objection in objections {
        if let driver::Objection::Warn(message) = objection {
            write_stderr(&format!("warning: {message}\n"))?;
        }
    }
    if let Some(refusal) = objections
        .iter()
        .find(|o| matches!(o, driver::Objection::Refuse(_)))
    {
        anyhow::bail!("{}", refusal.message());
    }
    Ok(())
}

/// Run a driven tool, mapping a failure to launch onto a message that names it.
async fn spawn_driven(
    mut command: tokio::process::Command,
    show_stderr: bool,
) -> anyhow::Result<std::process::ExitStatus> {
    let program = command
        .as_std()
        .get_program()
        .to_string_lossy()
        .into_owned();
    // Same reason as `spawn_child`: the session deletes what it lent this tool
    // — a browser profile, a trust bundle — when it ends, so a detached child
    // would be reading and writing a directory that is going away.
    command.kill_on_drop(true);
    if !show_stderr {
        command.stderr(std::process::Stdio::null());
    }
    command
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run `{program}`: {e}"))
}

/// Print findings as their transactions commit.
///
/// Reads the live capture feed: the proxy has already run the rules over each
/// transaction by the time it writes one, so the findings are there to be
/// printed and re-linting them would be work done twice for the same answer.
/// The end-of-session summary reads those same recorded findings through the
/// same [`gated_block`], so the tally and the lines above it are counting one
/// set of findings. They were not: the summary used to replay, and a replay
/// cannot see a body, so blocks scrolled past that the number at the bottom
/// left out.
async fn live_reporter(
    mut events: tokio::sync::broadcast::Receiver<std::sync::Arc<capture::CaptureEnvelope>>,
    scope: HostScope,
    min_severity: lint::Severity,
) {
    loop {
        let envelope = match events.recv().await {
            Ok(envelope) => envelope,
            // A session that outruns the channel loses lines here, never
            // findings: the summary is replayed from the file at the end.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let _ = write_stderr(&format!("  ... {n} record(s) not shown live\n"));
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };

        // Both record kinds, because both reach the summary. A WebSocket
        // session that was only counted and never printed would show up as a
        // number with nothing behind it — it commits once, when the session
        // ends, which is exactly when there is something to say about it.
        let Some(block) = gated_block(&envelope.record, min_severity) else {
            continue;
        };
        if !scope.keeps(&block) {
            continue;
        }
        if let Ok(text) = render_findings_block(&block) {
            let _ = write_stderr(&text);
        }
    }
}

/// Run the selected subcommand and return the process exit code (`0` success,
/// `1` lint findings). Real errors propagate as `Err` (anyhow maps them to exit
/// 1 with a message). Split from `main` so the dispatch is unit-testable without
/// spawning the process.
async fn dispatch(cli: Cli) -> anyhow::Result<u8> {
    let global = cli.global;
    // The three commands that stand a proxy up, and therefore the three that
    // have diagnostics worth hearing. The catalogue and config printers are
    // left alone so their stdout stays exactly what a pipe expects.
    if matches!(
        cli.command,
        Some(Command::Run(_) | Command::Browse(_) | Command::ProxyStart)
    ) {
        init_diagnostics();
    }
    match cli.command {
        Some(Command::Run(args)) => run_wrapped(args, &global).await,
        Some(Command::Browse(args)) => browse(args, &global).await,
        Some(Command::ProxyStart) => {
            run_app(global.config.as_deref(), global.captures.as_deref()).await?;
            Ok(0)
        }
        // Non-zero exit when findings exist, so CI fails on a dirty capture;
        // real errors (bad config / missing file) still bubble up as `Err`.
        Some(Command::LintCaptures(args)) => {
            let found = lint_app(
                global.config.as_deref(),
                &args.path(&global)?,
                global.format(),
                global.min_severity(),
            )
            .await?;
            Ok(if found > 0 { 1 } else { 0 })
        }
        Some(Command::Rules(args)) => match args.command {
            RulesCommand::List => {
                // `--config` unset means "do not annotate", not "annotate
                // against the built-in": this listing is the static catalogue,
                // and adding a column by default would change what every
                // existing reader of it parses.
                let cfg = match &global.config {
                    Some(path) => Some(load_validated_config(Some(path)).await?),
                    None => None,
                };
                write_stdout(&rules_list(global.format(), cfg.as_deref())?)?;
                Ok(0)
            }
        },
        Some(Command::Config(args)) => match args.command {
            // The bytes the binary runs with, not a rendering of them — so what
            // the user edits is what was in force before they edited it.
            ConfigCommand::Export => {
                write_stdout(config::DEFAULT_CONFIG_TOML)?;
                Ok(0)
            }
        },
        None => anyhow::bail!(
            "no command given; try `lint-http run -- curl https://example.com` (see `lint-http --help`)"
        ),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    Ok(std::process::ExitCode::from(dispatch(Cli::parse()).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use tokio::fs;
    use uuid::Uuid;

    /// A global option parses on either side of the subcommand, and means the
    /// same thing in both places.
    #[test]
    fn a_global_option_parses_before_or_after_the_subcommand() {
        for argv in [
            ["lint-http", "proxy-start", "--config", "x.toml"],
            ["lint-http", "--config", "x.toml", "proxy-start"],
        ] {
            let cli = Cli::parse_from(argv);
            assert!(matches!(cli.command, Some(Command::ProxyStart)));
            assert_eq!(cli.global.config.as_deref(), Some("x.toml"), "{argv:?}");
        }
    }

    /// Every command that takes one may omit it, which is what makes the
    /// built-in configuration reachable without a file on disk.
    #[test]
    fn config_is_optional_everywhere_it_is_accepted() {
        for argv in [
            vec!["lint-http", "proxy-start"],
            vec!["lint-http", "lint-captures", "caps.jsonl"],
            vec!["lint-http", "run", "--", "true"],
            vec!["lint-http", "browse"],
        ] {
            let cli = Cli::parse_from(&argv);
            assert!(cli.global.config.is_none(), "{argv:?}");
        }
    }

    /// The defaults live on `GlobalArgs`, not on four copies of each flag, so
    /// every command that reads one reads the same value.
    #[test]
    fn global_defaults_are_defined_once() {
        let global = Cli::parse_from(["lint-http", "run", "--", "true"]).global;
        assert!(matches!(global.format(), OutputFormat::Text));
        assert_eq!(global.min_severity(), lint::Severity::Info);
        assert!(global.captures_path().is_none());
    }

    #[test]
    fn cli_no_args_has_no_command() {
        let cli = Cli::parse_from(["lint-http"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_lint_captures_parses_config_and_captures() {
        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--config",
            "c.toml",
            "caps.jsonl",
        ]);
        assert_eq!(cli.global.config.as_deref(), Some("c.toml"));
        match cli.command {
            Some(Command::LintCaptures(args)) => {
                assert_eq!(args.path(&cli.global).unwrap(), "caps.jsonl");
            }
            other => panic!("expected LintCaptures, got {other:?}"),
        }
    }

    /// The capture file has one name across the whole surface: what `run`
    /// writes with `--captures` is what `lint-captures` reads, spelled either
    /// way. Naming it twice is refused rather than silently resolved.
    #[test]
    fn lint_captures_takes_the_file_from_either_spelling() {
        let flag = Cli::parse_from(["lint-http", "lint-captures", "--captures", "c.jsonl"]);
        match flag.command {
            Some(Command::LintCaptures(ref args)) => {
                assert_eq!(args.path(&flag.global).unwrap(), "c.jsonl");
            }
            ref other => panic!("expected LintCaptures, got {other:?}"),
        }

        let both = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--captures",
            "a.jsonl",
            "b.jsonl",
        ]);
        match both.command {
            Some(Command::LintCaptures(ref args)) => {
                assert!(args.path(&both.global).is_err(), "two spellings accepted");
            }
            ref other => panic!("expected LintCaptures, got {other:?}"),
        }

        let neither = Cli::parse_from(["lint-http", "lint-captures"]);
        match neither.command {
            Some(Command::LintCaptures(ref args)) => {
                assert!(args.path(&neither.global).is_err(), "no file accepted");
            }
            ref other => panic!("expected LintCaptures, got {other:?}"),
        }
    }

    /// The wrapped command is collected whole, and its own flags are its own:
    /// `--config` after the `--` belongs to curl, not to lint-http.
    #[test]
    fn cli_run_collects_the_child_command_and_its_flags() {
        let cli = Cli::parse_from([
            "lint-http",
            "run",
            "--min-severity",
            "warn",
            "--",
            "curl",
            "-sS",
            "--config",
            "curlrc",
            "https://example.com",
        ]);
        // The global was given *before* the `--`, so it is lint-http's; the one
        // after belongs to curl and must survive untouched in the child's argv.
        assert!(
            cli.global.config.is_none(),
            "--config after -- is the child's"
        );
        assert_eq!(cli.global.min_severity(), lint::Severity::Warn);
        match cli.command {
            Some(Command::Run(args)) => {
                assert_eq!(
                    args.command,
                    ["curl", "-sS", "--config", "curlrc", "https://example.com"]
                );
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_run_fail_on_is_absent_by_default() {
        match Cli::parse_from(["lint-http", "run", "--", "true"]).command {
            Some(Command::Run(args)) => assert!(args.session.fail_on.is_none()),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn cli_config_export_parses() {
        match Cli::parse_from(["lint-http", "config", "export"]).command {
            Some(Command::Config(args)) => assert!(matches!(args.command, ConfigCommand::Export)),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    /// The built-in configuration is a real configuration: it parses, it passes
    /// the same per-rule validation a file does, and it enables the catalogue
    /// rather than shipping an empty rule table that would lint nothing.
    #[tokio::test]
    async fn builtin_config_is_valid_and_enables_rules() -> anyhow::Result<()> {
        let cfg = load_validated_config(None).await?;
        let enabled = rules::RULES
            .iter()
            .filter(|r| cfg.is_enabled(r.id()))
            .count();
        assert!(
            enabled > 100,
            "built-in config enabled only {enabled} rules"
        );
        Ok(())
    }

    /// `config export` hands back exactly what the binary would have run, so a
    /// user who exports, changes nothing, and passes it back gets the same
    /// behaviour.
    #[tokio::test]
    async fn exported_config_round_trips() -> anyhow::Result<()> {
        let exported = config::DEFAULT_CONFIG_TOML;
        let parsed = config::Config::from_toml_str(exported)?;
        rules::validate_rules(&parsed)?;
        let builtin = load_validated_config(None).await?;
        assert_eq!(parsed.general.listen, builtin.general.listen);
        assert_eq!(
            rules::RULES
                .iter()
                .filter(|r| parsed.is_enabled(r.id()))
                .count(),
            rules::RULES
                .iter()
                .filter(|r| builtin.is_enabled(r.id()))
                .count()
        );
        Ok(())
    }

    /// Every variable the table names shows up in the preview, so `--print-env`
    /// cannot drift from what a run actually sets.
    /// `--print-env` previews the values a run really sets, not a second
    /// rendering of them: it named the bare CA where a run passes the trust
    /// bundle, and pointing a client at the bare CA replaces its trust instead
    /// of extending it.
    #[test]
    fn print_env_preview_names_the_file_a_run_actually_passes() {
        let preview = render_env_preview();
        assert!(
            preview.contains("trust-bundle.crt"),
            "preview did not name the bundle:\n{preview}"
        );
        assert!(
            !preview.contains("<tmp>/ca.crt"),
            "preview still names the bare CA:\n{preview}"
        );
        assert!(
            preview.contains("<port>"),
            "preview lost its port placeholder"
        );
    }

    #[test]
    fn print_env_preview_lists_every_variable() {
        let preview = render_env_preview();
        for var in client_env::CLIENT_ENV {
            assert!(preview.contains(var.name), "missing {}", var.name);
        }
    }

    // Write a minimal config that enables exactly one rule at `warn` and return
    // its temp path.
    async fn write_config_enabling(
        rule_id: &str,
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<std::path::PathBuf> {
        let tmp = temp.path("lint_lint_cfg", "toml");
        let toml = format!(
            r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.{rule_id}]
enabled = true
"#
        );
        fs::write(&tmp, toml).await?;
        Ok(tmp)
    }

    // Enables `cache_control_present` (fires on a 200 response without a
    // Cache-Control header).
    async fn write_cache_control_config(
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<std::path::PathBuf> {
        write_config_enabling("cache_control_present", temp).await
    }

    // Serialize transactions into a JSONL capture file (one versioned envelope per
    // line) the way the proxy's CaptureWriter would, and return its temp path.
    async fn write_capture_file(
        txs: &[lint_http::http_transaction::HttpTransaction],
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<std::path::PathBuf> {
        let tmp = temp.path("lint_lint_caps", "jsonl");
        let mut body = String::new();
        for tx in txs {
            let envelope = capture::CaptureEnvelope {
                schema_version: capture::CAPTURE_SCHEMA_VERSION,
                session: None,
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

        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_cache_control_config(&mut temp).await?;
        // 200 without Cache-Control -> one violation.
        let caps =
            write_capture_file(&[make_test_transaction_with_response(200, &[])], &mut temp).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
        let mut temp = crate::temp_files::TempFiles::new();
        use lint_http_core::test_helpers::make_test_transaction_with_response;
        let cfg = write_cache_control_config(&mut temp).await?;
        // 200 *with* Cache-Control -> the rule is satisfied, no violation.
        let caps = write_capture_file(
            &[make_test_transaction_with_response(
                200,
                &[("cache-control", "no-store")],
            )],
            &mut temp,
        )
        .await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_cache_control_config(&mut temp).await?;
        let caps = temp.path("lint_lint_empty", "jsonl");
        fs::write(&caps, "").await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_cache_control_config(&mut temp).await?;
        let result = lint_app(
            Some(cfg.to_str().unwrap()),
            "/nonexistent/does-not-exist.jsonl",
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await;
        assert!(result.is_err());

        fs::remove_file(&cfg).await?;
        Ok(())
    }

    // Enables only the WebSocket opcode-sequence protocol rule.
    async fn write_ws_opcode_config(
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<std::path::PathBuf> {
        write_config_enabling("websocket_frame_opcode_sequence", temp).await
    }

    fn ws_message(
        direction: lint_http::websocket_session::MessageDirection,
        opcode: u8,
        payload_length: u64,
    ) -> lint_http::websocket_session::WebSocketMessageInfo {
        lint_http::websocket_session::WebSocketMessageInfo {
            direction,
            opcode,
            payload_length,
            fin: true,
            rsv: 0,
            masked: None,
            timestamp: None,
        }
    }

    // Serialize a WebSocket session into a JSONL capture file the way the
    // proxy's CaptureWriter would, and return its temp path.
    async fn write_ws_capture_file(
        session: lint_http::websocket_session::WebSocketSession,
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<std::path::PathBuf> {
        let tmp = temp.path("lint_ws_caps", "jsonl");
        let envelope = capture::CaptureEnvelope::new(capture::CaptureRecord::WebsocketSession(
            Box::new(session),
        ));
        fs::write(&tmp, format!("{}\n", serde_json::to_string(&envelope)?)).await?;
        Ok(tmp)
    }

    #[tokio::test]
    async fn lint_replays_websocket_sessions_through_protocol_rules() -> anyhow::Result<()> {
        use lint_http::websocket_session::{MessageDirection, WebSocketSession};
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_ws_opcode_config(&mut temp).await?;
        // Reserved opcode 3 → one violation from the opcode-sequence rule.
        let mut session = WebSocketSession::new(Uuid::new_v4());
        session
            .messages
            .push(ws_message(MessageDirection::Client, 3, 5));
        let caps = write_ws_capture_file(session, &mut temp).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
    async fn lint_websocket_data_after_close_is_flagged_statefully() -> anyhow::Result<()> {
        use lint_http::websocket_session::{MessageDirection, WebSocketSession};
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_ws_opcode_config(&mut temp).await?;
        // Close then a data frame in the same direction — only detectable when
        // the replay feeds prior frames into the session history.
        let mut session = WebSocketSession::new(Uuid::new_v4());
        session
            .messages
            .push(ws_message(MessageDirection::Client, 8, 2));
        session
            .messages
            .push(ws_message(MessageDirection::Client, 1, 4));
        session.close_code = Some(1000);
        let caps = write_ws_capture_file(session, &mut temp).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
    async fn lint_clean_websocket_session_reports_zero() -> anyhow::Result<()> {
        use lint_http::websocket_session::{MessageDirection, WebSocketSession};
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_ws_opcode_config(&mut temp).await?;
        let mut session = WebSocketSession::new(Uuid::new_v4());
        session
            .messages
            .push(ws_message(MessageDirection::Client, 1, 5));
        session
            .messages
            .push(ws_message(MessageDirection::Server, 1, 7));
        session
            .messages
            .push(ws_message(MessageDirection::Client, 8, 2));
        session.close_code = Some(1000);
        let caps = write_ws_capture_file(session, &mut temp).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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
    async fn lint_duplicate_session_records_do_not_contaminate() -> anyhow::Result<()> {
        use lint_http::websocket_session::{MessageDirection, WebSocketSession};
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_ws_opcode_config(&mut temp).await?;
        // A clean session (text then close) recorded TWICE in one capture —
        // e.g. concatenated capture files. Each replay must start from a fresh
        // history: the first replay's Close frame must not make the second
        // replay's text frame look like data-after-close.
        let mut session = WebSocketSession::new(Uuid::new_v4());
        session
            .messages
            .push(ws_message(MessageDirection::Client, 1, 5));
        session
            .messages
            .push(ws_message(MessageDirection::Client, 8, 2));
        session.close_code = Some(1000);

        let tmp = temp.path("lint_ws_dup", "jsonl");
        let envelope = capture::CaptureEnvelope::new(capture::CaptureRecord::WebsocketSession(
            Box::new(session),
        ));
        let line = serde_json::to_string(&envelope)?;
        fs::write(&tmp, format!("{line}\n{line}\n")).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
            tmp.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Info,
        )
        .await?;
        assert_eq!(found, 0);

        fs::remove_file(&cfg).await?;
        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn lint_min_severity_gates_findings_and_exit_code() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        // The finding this produces is `cache_control_missing`, whose entry
        // defaults to `info` — the level is the defect's, not the rule's, so
        // the `[rules.*]` table in the config no longer decides it. A `warn`
        // gate filters it out…
        let cfg = write_cache_control_config(&mut temp).await?;
        let caps =
            write_capture_file(&[make_test_transaction_with_response(200, &[])], &mut temp).await?;

        let found = lint_app(
            Some(cfg.to_str().unwrap()),
            caps.to_str().unwrap(),
            OutputFormat::Text,
            lint::Severity::Warn,
        )
        .await?;
        assert_eq!(found, 0, "info finding must not survive a warn gate");

        // …while an `info` gate keeps it.
        let found = lint_app(
            Some(cfg.to_str().unwrap()),
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

    #[test]
    fn cli_lint_parses_format_and_min_severity() {
        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--config",
            "c.toml",
            "--format",
            "json",
            "--min-severity",
            "warn",
            "caps.jsonl",
        ]);
        assert!(matches!(cli.command, Some(Command::LintCaptures(_))));
        assert!(matches!(cli.global.format(), OutputFormat::Json));
        assert_eq!(cli.global.min_severity(), lint::Severity::Warn);
    }

    #[test]
    fn cli_lint_captures_defaults_to_text_and_info() {
        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--config",
            "c.toml",
            "caps.jsonl",
        ]);
        assert!(matches!(cli.command, Some(Command::LintCaptures(_))));
        assert!(matches!(cli.global.format(), OutputFormat::Text));
        assert_eq!(cli.global.min_severity(), lint::Severity::Info);
    }

    /// A driven session reports what its own proxy found, and a body rule is
    /// the proof.
    ///
    /// `problem_details_structure_valid` reads `response_body`, which is
    /// `#[serde(skip)]` — it never comes back out of a capture file. Replaying
    /// that record under the very config the run used, with the rule enabled,
    /// therefore finds nothing; and for as long as `run` reported by replaying,
    /// a malformed problem document walked through a `--fail-on error` gate the
    /// proxy had already tripped.
    #[tokio::test]
    async fn a_body_rule_reaches_the_report_a_replay_cannot_reproduce() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let mut temp = crate::temp_files::TempFiles::new();
        let cfg_path = write_config_enabling("problem_details_structure_valid", &mut temp).await?;
        let cfg = load_validated_config(cfg_path.to_str()).await?;

        // The transaction as the live pass held it: a body in hand, and the
        // finding that body produced already on the record.
        let mut tx = make_test_transaction_with_response(
            400,
            &[("content-type", "application/problem+json")],
        );
        tx.response_body = Some(bytes::Bytes::from_static(b"this is not a JSON object"));
        tx.violations = vec![lint::Violation::new(
            "problem_details_structure_valid",
            lint::Severity::Error,
            "problem detail body is not a JSON object",
        )];

        // Through the file, which is where the body is lost and the finding is not.
        let captures = write_capture_file(&[tx], &mut temp).await?;
        let records = capture::load_capture_records(captures.to_str().unwrap()).await?;

        let reported = recorded_findings(&records, lint::Severity::Info);
        assert_eq!(reported.total(), 1, "the recorded finding must be reported");

        let replayed = lint_records(&cfg, records, lint::Severity::Info)?;
        assert_eq!(
            replayed.total(),
            0,
            "the replay is expected to miss it — that is the defect this reports around"
        );
        Ok(())
    }

    /// One gate, applied once, so the tally counts exactly the blocks a reader
    /// saw scroll past — which is what `browse` could not say while its live
    /// lines came off the record and its summary came off a replay.
    #[test]
    fn the_summary_counts_exactly_the_blocks_it_prints() {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let mut loud = make_test_transaction_with_response(200, &[]);
        loud.violations = vec![lint::Violation::new(
            "cache_control_present",
            lint::Severity::Warn,
            "missing Cache-Control",
        )];
        let mut quiet = make_test_transaction_with_response(200, &[]);
        quiet.violations = vec![lint::Violation::new(
            "user_agent_present",
            lint::Severity::Info,
            "no User-Agent",
        )];
        let clean = make_test_transaction_with_response(200, &[]);

        let records: Vec<capture::CaptureRecord> = [loud, quiet, clean]
            .into_iter()
            .map(|tx| capture::CaptureRecord::HttpTransaction(Box::new(tx)))
            .collect();

        let report = recorded_findings(&records, lint::Severity::Warn);
        assert_eq!(
            report.findings.len(),
            1,
            "only the warning survives the gate"
        );
        assert_eq!(report.total(), 1);
        // Every transaction is still counted, gated or not: the summary divides
        // findings by the traffic they were found in.
        assert_eq!(report.transaction_count, 3);

        // And the live path builds the same blocks from the same records,
        // because it builds them with the same function.
        let live: Vec<_> = records
            .iter()
            .filter_map(|record| gated_block(record, lint::Severity::Warn))
            .collect();
        assert_eq!(live.len(), report.findings.len());
    }

    /// A WebSocket session's findings are the relay's, for the same reason a
    /// transaction's are: the live pass watched the frames go by.
    #[test]
    fn a_websocket_session_reports_the_findings_the_relay_recorded() {
        use lint_http::websocket_session::WebSocketSession;

        let mut session = WebSocketSession::new(Uuid::new_v4());
        session.violations = vec![lint::Violation::new(
            "websocket_frame_opcode_sequence",
            lint::Severity::Error,
            "reserved opcode",
        )];
        let records = vec![capture::CaptureRecord::WebsocketSession(Box::new(session))];

        let report = recorded_findings(&records, lint::Severity::Info);
        assert_eq!(report.websocket_count, 1);
        assert_eq!(report.total(), 1);
    }

    fn sample_violation() -> lint::Violation {
        lint::Violation::new(
            "cache_control_present",
            lint::Severity::Warn,
            "missing Cache-Control",
        )
    }

    fn sample_findings() -> Vec<FindingsBlock> {
        vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![sample_violation()],
        })]
    }

    #[test]
    fn render_lint_report_json_mirrors_the_text_block() -> anyhow::Result<()> {
        let out = render_lint_report(&sample_findings(), 3, 0, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["kind"], "http_transaction");
        assert_eq!(parsed[0]["method"], "GET");
        assert_eq!(parsed[0]["status"], 200);
        assert_eq!(parsed[0]["violations"][0]["rule"], "cache_control_present");
        assert_eq!(parsed[0]["violations"][0]["severity"], "warn");
        Ok(())
    }

    #[test]
    fn render_lint_report_json_null_status_for_no_response() -> anyhow::Result<()> {
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: None,
            violations: vec![sample_violation()],
        })];
        let out = render_lint_report(&findings, 1, 0, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out)?;
        assert!(parsed[0]["status"].is_null());
        Ok(())
    }

    #[test]
    fn render_lint_report_text_appends_the_citation_when_present() -> anyhow::Result<()> {
        let mut v = sample_violation();
        v.cite = Some(lint::SpecCitation {
            spec: "RFC 9111".to_string(),
            section: Some("5.2".to_string()),
            url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2".to_string(),
        });
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v, sample_violation()],
        })];
        let out = render_lint_report(&findings, 1, 0, OutputFormat::Text)?;
        assert!(
            out.contains("[RFC 9111 §5.2 https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2]"),
            "{out}"
        );
        // The un-cited finding's line is unchanged — no empty bracket.
        assert!(!out.contains("[]"), "{out}");
        Ok(())
    }

    /// A finding that names a defect prints both names; one that does not
    /// prints the rule alone, with no stray separator. The JSON half needs no
    /// decision of its own — `violation` is a field, and it is present or
    /// skipped by the same rule.
    #[test]
    fn render_lint_report_text_names_the_defect_when_there_is_one() -> anyhow::Result<()> {
        let mut v = sample_violation();
        v.violation = "cache_control_missing".to_string();
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v, sample_violation()],
        })];
        let out = render_lint_report(&findings, 1, 0, OutputFormat::Text)?;
        assert!(
            out.contains("warn  cache_control_present/cache_control_missing  missing"),
            "{out}"
        );
        assert!(
            out.contains("warn  cache_control_present  missing"),
            "{out}"
        );

        let json = render_lint_report(&findings, 1, 0, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json)?;
        assert_eq!(
            parsed[0]["violations"][0]["violation"],
            "cache_control_missing"
        );
        assert!(parsed[0]["violations"][1]["violation"].is_null());
        Ok(())
    }

    #[test]
    fn render_lint_report_text_has_summary_line() -> anyhow::Result<()> {
        let out = render_lint_report(&sample_findings(), 3, 0, OutputFormat::Text)?;
        assert!(out.contains("GET http://example.test/ -> 200"));
        assert!(out.contains("warn  cache_control_present"));
        // No websocket sessions in the capture → summary is the pure-HTTP form.
        assert!(out.ends_with("1 violation(s) in 3 transaction(s)\n"));
        Ok(())
    }

    #[test]
    fn render_lint_report_websocket_block_in_both_formats() -> anyhow::Result<()> {
        let session_id = Uuid::new_v4();
        let transaction_id = Uuid::new_v4();
        let findings = vec![FindingsBlock::WebsocketSession(WebsocketFindings {
            session_id,
            transaction_id,
            close_code: Some(1000),
            violations: vec![sample_violation()],
        })];

        let text = render_lint_report(&findings, 0, 2, OutputFormat::Text)?;
        assert!(text.contains(&format!(
            "websocket session {session_id} (upgrade {transaction_id}) -> close 1000"
        )));
        assert!(text.ends_with("1 violation(s) in 0 transaction(s) and 2 websocket session(s)\n"));

        let json = render_lint_report(&findings, 0, 2, OutputFormat::Json)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json)?;
        assert_eq!(parsed[0]["kind"], "websocket_session");
        assert_eq!(parsed[0]["session_id"], session_id.to_string());
        assert_eq!(parsed[0]["close_code"], 1000);
        Ok(())
    }

    // Write a minimal config whose `listen` points at an already-bound port, so
    // `run_app` fails fast at bind — lets the dispatch tests exercise the `run`
    // and legacy arms without the proxy blocking.
    async fn write_port_taken_config(
        addr: std::net::SocketAddr,
        temp: &mut crate::temp_files::TempFiles,
    ) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
        let cfg = temp.path("lint_dispatch_cfg", "toml");
        let caps = temp.path("lint_dispatch_caps", "jsonl");
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
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_cache_control_config(&mut temp).await?;
        let caps =
            write_capture_file(&[make_test_transaction_with_response(200, &[])], &mut temp).await?;
        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
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
        let mut temp = crate::temp_files::TempFiles::new();
        use lint_http_core::test_helpers::make_test_transaction_with_response;
        let cfg = write_cache_control_config(&mut temp).await?;
        let caps = write_capture_file(
            &[make_test_transaction_with_response(
                200,
                &[("cache-control", "no-store")],
            )],
            &mut temp,
        )
        .await?;
        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
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
    async fn dispatch_proxy_start_routes_to_run_app() -> anyhow::Result<()> {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;
        let mut temp = crate::temp_files::TempFiles::new();
        let (cfg, caps) = write_port_taken_config(addr, &mut temp).await?;
        let cli = Cli::parse_from([
            "lint-http",
            "proxy-start",
            "--config",
            cfg.to_str().unwrap(),
        ]);
        // run_app binds the already-taken port and errors fast.
        assert!(dispatch(cli).await.is_err());
        let _ = fs::remove_file(&cfg).await;
        let _ = fs::remove_file(&caps).await;
        drop(l);
        Ok(())
    }

    /// The bare `--config` alias is gone rather than repointed. It used to mean
    /// "start the proxy", and `run` now means "wrap a command" — an alias that
    /// kept working would start a proxy for someone who asked for neither.
    ///
    /// Now that `--config` is global it *parses* at the top level, as it must
    /// to be accepted before a subcommand. What it no longer does is stand in
    /// for one: with nothing to run, dispatch says so instead of starting
    /// anything.
    #[tokio::test]
    async fn bare_config_starts_nothing() {
        let cli = Cli::parse_from(["lint-http", "--config", "x.toml"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.global.config.as_deref(), Some("x.toml"));
        assert!(
            dispatch(cli).await.is_err(),
            "a bare --config ran something"
        );
    }

    /// A wrapped run reports what crossed the proxy and hands back the child's
    /// exit code — the whole command, through `dispatch`, as a user runs it.
    #[tokio::test]
    async fn dispatch_run_wraps_a_command_and_keeps_its_exit_code() -> anyhow::Result<()> {
        let cli = Cli::parse_from(["lint-http", "run", "--", "sh", "-c", "exit 5"]);
        assert_eq!(dispatch(cli).await?, 5);
        Ok(())
    }

    /// `--fail-on` is the only thing that lets a finding decide the exit code,
    /// and with nothing found it changes nothing.
    #[tokio::test]
    async fn dispatch_run_fail_on_is_quiet_when_nothing_was_found() -> anyhow::Result<()> {
        let cli = Cli::parse_from(["lint-http", "run", "--fail-on", "error", "--", "true"]);
        assert_eq!(dispatch(cli).await?, 0);
        Ok(())
    }

    /// A child that failed keeps its own code even under `--fail-on`: its
    /// failure is the more specific answer, and flattening it to 1 would lose
    /// the distinction every test runner encodes in its exit codes.
    #[tokio::test]
    async fn dispatch_run_child_failure_outranks_fail_on() -> anyhow::Result<()> {
        let cli = Cli::parse_from([
            "lint-http",
            "run",
            "--fail-on",
            "info",
            "--",
            "sh",
            "-c",
            "exit 9",
        ]);
        assert_eq!(dispatch(cli).await?, 9);
        Ok(())
    }

    /// The documented composition: a gate above the finding's severity filters
    /// it out of the report, and `--fail-on` then has nothing to fail on. Pinned
    /// because the alternative reading — fail on findings that were never shown
    /// — is the one a reader expects until they hit it.
    #[tokio::test]
    async fn fail_on_reads_the_gated_report() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let mut temp = crate::temp_files::TempFiles::new();
        let cfg = write_cache_control_config(&mut temp).await?;
        // A 200 without Cache-Control: one finding, reported at `info`.
        let caps =
            write_capture_file(&[make_test_transaction_with_response(200, &[])], &mut temp).await?;

        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--config",
            cfg.to_str().unwrap(),
            "--min-severity",
            "info",
            caps.to_str().unwrap(),
        ]);
        assert_eq!(
            dispatch(cli).await?,
            1,
            "an info finding should be reported"
        );

        let cli = Cli::parse_from([
            "lint-http",
            "lint-captures",
            "--config",
            cfg.to_str().unwrap(),
            "--min-severity",
            "error",
            caps.to_str().unwrap(),
        ]);
        assert_eq!(dispatch(cli).await?, 0, "a gated-out finding must not fail");
        Ok(())
    }

    /// A mistyped lint-http option lands in the child's argv, because that is
    /// the price of letting the child keep its own flags. It must be named as
    /// such rather than surfacing as a missing program — and before a proxy is
    /// stood up for it.
    #[tokio::test]
    async fn dispatch_run_rejects_a_flag_where_a_command_belongs() {
        let cli = Cli::parse_from(["lint-http", "run", "--", "--fail-onn", "error"]);
        let err = dispatch(cli).await.expect_err("a flag is not a command");
        let msg = err.to_string();
        assert!(msg.contains("--fail-onn"), "message was {msg:?}");
        assert!(msg.contains("before `--`"), "message was {msg:?}");
    }

    #[tokio::test]
    async fn dispatch_run_without_a_command_is_an_error() {
        let cli = Cli::parse_from(["lint-http", "run"]);
        assert!(dispatch(cli).await.is_err());
    }

    #[tokio::test]
    async fn dispatch_config_export_emits_the_builtin() -> anyhow::Result<()> {
        let cli = Cli::parse_from(["lint-http", "config", "export"]);
        assert_eq!(dispatch(cli).await?, 0);
        Ok(())
    }

    #[test]
    fn uri_host_reads_the_shapes_a_capture_holds() {
        assert_eq!(uri_host("https://example.com/a/b?c=1"), Some("example.com"));
        assert_eq!(uri_host("http://example.com:8080/"), Some("example.com"));
        // Authority-form, as a CONNECT target is recorded.
        assert_eq!(uri_host("example.com:443"), Some("example.com"));
        assert_eq!(
            uri_host("https://user:pw@example.com/x"),
            Some("example.com")
        );
        // The colons inside the brackets are the address, not a port.
        assert_eq!(uri_host("https://[::1]:8080/x"), Some("::1"));
        // Nothing to read: an origin-form target.
        assert_eq!(uri_host("/just/a/path"), None);
    }

    /// A URL in a query string is not the target's host. Scoping on it drops a
    /// first-party finding for naming a third party.
    #[test]
    fn uri_host_ignores_a_scheme_after_the_path_begins() {
        assert_eq!(
            uri_host("/oauth/callback?redirect_uri=https://cdn.other.net/x"),
            None
        );
        assert_eq!(uri_host("/a/b#https://x.example/"), None);
        // The real thing still parses.
        assert_eq!(uri_host("https://example.com/a"), Some("example.com"));
    }

    /// `--only-host localhost:3000` has to match a target whose host is
    /// `localhost` — the port is stripped from one side, so it must be stripped
    /// from the other, or the scope matches nothing and reports a clean nothing.
    #[test]
    fn a_scope_entry_may_carry_a_port() {
        let scope = HostScope::new(["localhost:3000".to_string()]);
        assert!(scope.includes("http://localhost:3000/app"));
        assert!(scope.includes("http://localhost/app"));
        assert!(!scope.includes("http://example.com/"));
    }

    #[test]
    fn a_scope_entry_is_matched_case_insensitively_however_it_was_typed() {
        let scope = HostScope::new(["EXAMPLE.com".to_string()]);
        assert!(scope.includes("https://example.com/"));
        assert!(scope.includes("https://API.Example.COM/"));
    }

    #[test]
    fn a_scope_covers_its_host_and_what_is_under_it() {
        let scope = HostScope {
            hosts: vec!["example.com".to_string()],
        };
        assert!(scope.includes("https://example.com/"));
        assert!(scope.includes("https://www.example.com/"));
        assert!(scope.includes("https://api.example.com/v1"));
        assert!(scope.includes("https://EXAMPLE.COM/"));
        // The dot is what stops it swallowing a different registration.
        assert!(!scope.includes("https://notexample.com/"));
        assert!(!scope.includes("https://cdn.other.net/"));
    }

    /// A target with no host widens the report rather than narrowing it: a
    /// finding dropped for a reason the reader cannot see is worse than one
    /// shown that they did not ask for.
    #[test]
    fn a_target_with_no_host_is_kept() {
        let scope = HostScope {
            hosts: vec!["example.com".to_string()],
        };
        assert!(scope.includes("/just/a/path"));
    }

    #[test]
    fn an_empty_scope_is_every_host() {
        assert!(HostScope::all().includes("https://anything.example/"));
        assert!(HostScope::all().is_all());
    }

    /// The count is of findings, not transactions — it exists to answer "is the
    /// default hiding something I want to see".
    #[test]
    fn apply_counts_the_findings_it_left_out() {
        let mine = FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".into(),
            uri: "https://example.com/".into(),
            status: Some(200),
            violations: vec![sample_violation()],
        });
        let theirs = FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".into(),
            uri: "https://cdn.other.net/x.js".into(),
            status: Some(200),
            violations: vec![sample_violation(), sample_violation()],
        });
        let scope = HostScope {
            hosts: vec!["example.com".to_string()],
        };
        let (kept, elsewhere) = scope.apply(vec![mine, theirs]);
        assert_eq!(kept.len(), 1);
        assert_eq!(elsewhere, 2);
    }

    /// A WebSocket session is kept whatever the scope: it exists because an
    /// upgrade was made deliberately, and its record carries no target anyway.
    #[test]
    fn a_websocket_session_survives_scoping() {
        let ws = FindingsBlock::WebsocketSession(WebsocketFindings {
            session_id: Uuid::new_v4(),
            transaction_id: Uuid::new_v4(),
            close_code: Some(1000),
            violations: vec![sample_violation()],
        });
        let scope = HostScope {
            hosts: vec!["example.com".to_string()],
        };
        let (kept, elsewhere) = scope.apply(vec![ws]);
        assert_eq!(kept.len(), 1);
        assert_eq!(elsewhere, 0);
    }

    /// The four session options are the same four on every command that starts
    /// a child, which they were not: `run` had no way to say which hosts it
    /// cared about and `browse` had no way to fail on anything it found.
    #[test]
    fn a_session_option_means_the_same_thing_on_every_session_command() {
        let run = Cli::parse_from([
            "lint-http",
            "run",
            "--fail-on",
            "error",
            "--only-host",
            "api.example.com",
            "--",
            "curl",
            "https://api.example.com/",
        ]);
        match run.command {
            Some(Command::Run(args)) => {
                assert!(matches!(args.session.fail_on, Some(SeverityArg::Error)));
                assert_eq!(args.session.only_host, ["api.example.com"]);
            }
            other => panic!("expected Run, got {other:?}"),
        }

        let browse = Cli::parse_from([
            "lint-http",
            "browse",
            "--fail-on",
            "warn",
            "https://example.com/",
        ]);
        match browse.command {
            Some(Command::Browse(args)) => {
                assert!(matches!(args.session.fail_on, Some(SeverityArg::Warn)));
            }
            other => panic!("expected Browse, got {other:?}"),
        }
    }

    /// The scope a session reports, in the order the three inputs win.
    #[test]
    fn a_session_scopes_to_its_target_unless_told_otherwise() {
        let target = Some("https://example.com/app");

        // Nothing said, and a target to infer from: that target's host.
        let inferred = SessionArgs::default().scope(target);
        assert!(inferred.includes("https://api.example.com/v1"));
        assert!(!inferred.includes("https://cdn.other.net/x"));

        // Nothing said and no target — `run --`, which cannot know one.
        assert!(SessionArgs::default().scope(None).is_all());

        // `--only-host` replaces the inferred first party rather than adding to it.
        let named = SessionArgs {
            only_host: vec!["cdn.other.net".to_string()],
            ..SessionArgs::default()
        };
        let named = named.scope(target);
        assert!(named.includes("https://cdn.other.net/x"));
        assert!(!named.includes("https://example.com/app"));

        // `--all-hosts` outranks both.
        let all = SessionArgs {
            all_hosts: true,
            only_host: vec!["cdn.other.net".to_string()],
            ..SessionArgs::default()
        };
        assert!(all.scope(target).is_all());
    }

    /// A finding never overrides a child that failed, and a clean lint never
    /// overrides anything at all.
    #[test]
    fn a_session_exit_prefers_the_child_and_then_the_gate() {
        let dirty = sample_findings(); // one warning
        assert_eq!(session_exit(0, None, &dirty), 0, "no gate, no failure");
        assert_eq!(session_exit(0, Some(SeverityArg::Warn), &dirty), 1);
        assert_eq!(
            session_exit(0, Some(SeverityArg::Error), &dirty),
            0,
            "the gate reads the severity it was given"
        );
        assert_eq!(
            session_exit(3, Some(SeverityArg::Warn), &dirty),
            3,
            "the child's own code is the more specific answer"
        );
        assert_eq!(session_exit(0, Some(SeverityArg::Info), &[]), 0);
        // An exit code that does not fit a u8 is an abnormal end, not a success.
        assert_eq!(session_exit(-1, None, &[]), 1);
    }

    #[test]
    fn cli_browse_defaults_scope_to_the_url_host() {
        match Cli::parse_from(["lint-http", "browse", "https://example.com/app"]).command {
            Some(Command::Browse(args)) => {
                assert!(args.session.only_host.is_empty());
                assert!(!args.session.all_hosts);
                assert_eq!(args.url.as_deref(), Some("https://example.com/app"));
            }
            other => panic!("expected Browse, got {other:?}"),
        }
    }

    #[test]
    fn cli_browse_rejects_scoping_two_ways_at_once() {
        assert!(Cli::try_parse_from([
            "lint-http",
            "browse",
            "--all-hosts",
            "--only-host",
            "example.com",
        ])
        .is_err());
    }

    /// A warning lets the session run and a refusal does not, which is the
    /// whole difference between the two.
    #[test]
    fn a_refusal_stops_a_session_and_a_warning_does_not() {
        assert!(raise(&[driver::Objection::Warn("odd but survivable".into())]).is_ok());
        let Err(err) = raise(&[
            driver::Objection::Warn("odd but survivable".into()),
            driver::Objection::Refuse("there would be nothing to report".into()),
        ]) else {
            panic!("a refusal must stop the session");
        };
        assert!(
            err.to_string().contains("nothing to report"),
            "the refusal must say why: {err}"
        );
    }

    /// The session options are grouped, and the group ends where they do.
    ///
    /// `next_help_heading` runs from where a flattened struct is declared to
    /// the end of the argument list, so flattening `SessionArgs` first files
    /// `--print-env` and the wrapped command under "Session options" — where
    /// neither belongs, and where nobody reading the source would look for
    /// them.
    #[test]
    fn the_session_group_holds_the_session_options_and_no_others() {
        let run = Cli::command()
            .get_subcommands()
            .find(|c| c.get_name() == "run")
            .expect("run is a subcommand")
            .clone()
            .render_long_help()
            .to_string();
        let session = run
            .split("Session options:")
            .nth(1)
            .expect("the group is rendered");
        for flag in [
            "--fail-on",
            "--only-host",
            "--all-hosts",
            "--show-child-stderr",
        ] {
            assert!(session.contains(flag), "the group lost {flag}");
        }
        assert!(
            !session.contains("--print-env"),
            "--print-env is not a session option"
        );
    }

    /// `--help` is user-facing text, and a flattened struct's doc comment lands
    /// in it by default. `GlobalArgs`' explains *why* those options are global,
    /// which belongs to whoever edits this file — pinned because the leak is
    /// invisible from the source and only shows up when someone runs the binary.
    #[test]
    fn help_does_not_carry_the_notes_meant_for_this_file() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("HTTP-linting forward proxy"),
            "the binary lost its description"
        );
        for leaked in [
            "redeclared per command",
            "global = true",
            "drift in its default",
            // `SessionArgs`' own note, which is for whoever edits this file.
            "diverged, in both directions",
        ] {
            assert!(!help.contains(leaked), "help leaked {leaked:?}");
        }
        // The four are still there, and grouped.
        assert!(help.contains("Global options"));
        for flag in ["--config", "--format", "--min-severity", "--captures"] {
            assert!(help.contains(flag), "help lost {flag}");
        }
    }

    #[test]
    fn cli_rules_list_parses_format() {
        let cli = Cli::parse_from(["lint-http", "rules", "list", "--format", "json"]);
        assert!(matches!(cli.command, Some(Command::Rules(_))));
        assert!(matches!(cli.global.format(), OutputFormat::Json));
    }

    #[test]
    fn cli_rules_list_defaults_to_text() {
        let cli = Cli::parse_from(["lint-http", "rules", "list"]);
        assert!(matches!(cli.command, Some(Command::Rules(_))));
        assert!(matches!(cli.global.format(), OutputFormat::Text));
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
        assert!(out.contains("cache_control_present"));
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
            .find(|v| v["id"] == "cache_control_present")
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
        // The fixture config enables exactly `cache_control_present`.
        let mut temp = crate::temp_files::TempFiles::new();
        let cfg_path = write_cache_control_config(&mut temp).await?;
        let cfg = load_validated_config(Some(cfg_path.to_str().unwrap())).await?;

        let text = rules_list(OutputFormat::Text, Some(&cfg))?;
        let line = text
            .lines()
            .find(|l| l.starts_with("cache_control_present"))
            .expect("rule line present");
        assert!(line.contains(" enabled "));
        assert!(text.contains(" disabled "));

        let json = rules_list(OutputFormat::Json, Some(&cfg))?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json)?;
        let cc = parsed
            .iter()
            .find(|v| v["id"] == "cache_control_present")
            .expect("known rule present");
        assert_eq!(cc["enabled"], true);
        assert!(parsed.iter().any(|v| v["enabled"] == false));

        fs::remove_file(&cfg_path).await?;
        Ok(())
    }

    #[test]
    fn cli_rules_list_parses_optional_config() {
        let cli = Cli::parse_from(["lint-http", "rules", "list", "--config", "c.toml"]);
        assert!(matches!(cli.command, Some(Command::Rules(_))));
        assert_eq!(cli.global.config.as_deref(), Some("c.toml"));
    }

    #[tokio::test]
    async fn dispatch_rules_list_returns_0() -> anyhow::Result<()> {
        let cli = Cli::parse_from(["lint-http", "rules", "list"]);
        assert_eq!(dispatch(cli).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn main_cli_config_loads_toml() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_main_cli_cfg", "toml");
        let toml = r#"[rules]
    [rules.cache_control_present]
    enabled = false

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

        assert!(!cfg.is_enabled("cache_control_present"));
        assert_eq!(cfg.general.listen, "127.0.0.1:3000");

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn main_rejects_invalid_rule_config_before_proxy_starts() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_main_cli_cfg_invalid", "toml");
        let toml = r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

 [rules.clear_site_data_present]
 enabled = true
 paths = []  # Invalid: empty paths array
"#;
        fs::write(&tmp, toml).await?;

        let config_path = tmp.to_str().expect("valid utf8 path");

        // run_app must fail during rule validation, before binding any socket.
        let result = run_app(Some(config_path), None).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("clear_site_data_present"));
        assert!(err_msg.contains("cannot be empty"));

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn run_app_with_limit_starts_and_returns() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        // Pick a free port
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = l.local_addr()?.port();
        drop(l);
        let tmp = temp.path("lint_main_with_limit", "toml");
        let capture_path = temp.path("captures", "jsonl");
        let toml = format!(
            r#"[rules]
[rules.cache_control_present]
enabled = false

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
        let task =
            tokio::spawn(async move { run_app_with_limit(Some(&config_path), Some(1)).await });

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
        Ok(())
    }

    #[tokio::test]
    async fn run_app_errors_when_port_taken() -> anyhow::Result<()> {
        // Reserve a port by binding a TcpListener
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = l.local_addr()?;

        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_main_port_taken", "toml");
        let capture_path = temp.path("captures", "jsonl");
        let toml = format!(
            r#"[rules]
[rules.cache_control_present]
enabled = false

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
        let res = run_app(Some(config_path), None).await;
        assert!(res.is_err());

        // Cleanup
        drop(l);
        Ok(())
    }
}
