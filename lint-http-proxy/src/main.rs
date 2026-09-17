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
    browser, capture, client_env, config, engine, lint, protocol_event_store, proxied_run, proxy,
    rules, state,
};

#[derive(Parser, Debug)]
#[command(name = "lint-http", version, about = "HTTP-linting forward proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
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
    ProxyStart(ProxyStartArgs),
    /// Lint a recorded capture file, replaying its transactions and WebSocket
    /// sessions through the rules.
    #[command(name = "lint-captures")]
    LintCaptures(LintArgs),
    /// Inspect the rule catalogue.
    Rules(RulesArgs),
    /// Work with the configuration itself.
    Config(ConfigArgs),
}

#[derive(clap::Args, Debug)]
struct ProxyStartArgs {
    /// Config TOML path (rule toggles, listen address, captures path).
    /// Defaults to the built-in configuration.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
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
    /// Config TOML path. Defaults to the built-in configuration.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
    /// Output format for the findings report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Only report findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    min_severity: SeverityArg,
    /// Exit non-zero when a finding *in the report* reaches this severity —
    /// findings `--min-severity` filtered out cannot trip it. Without this, the
    /// exit code is the wrapped command's.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<SeverityArg>,
    /// Keep the capture file at this path instead of discarding it.
    #[arg(long, value_name = "PATH")]
    captures: Option<String>,
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
}

/// `lint-http browse [URL]`
///
/// A browsing session against a proxy that exists only for it: a throwaway
/// profile, a CA trusted for this launch by public-key pin, and findings
/// printed as they happen. Nothing is installed and nothing is left behind.
#[derive(clap::Args, Debug)]
struct BrowseArgs {
    /// Config TOML path. Defaults to the built-in configuration.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
    /// Browser executable to use. Defaults to the first Chromium-family
    /// browser found.
    #[arg(long, value_name = "PATH")]
    browser: Option<String>,
    /// Report findings for this host and anything under it. Repeatable.
    /// Defaults to the host of URL.
    #[arg(long, value_name = "HOST")]
    only_host: Vec<String>,
    /// Report every host, including third parties the page pulls in.
    #[arg(long, conflicts_with = "only_host")]
    all_hosts: bool,
    /// Output format. `json` prints one report at the end instead of findings
    /// as they happen.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Only report findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    min_severity: SeverityArg,
    /// Keep the capture file at this path instead of discarding it.
    #[arg(long, value_name = "PATH")]
    captures: Option<String>,
    /// Where to open. Omitted, the browser opens its own start page and
    /// whatever it fetches is still linted.
    #[arg(value_name = "URL")]
    url: Option<String>,
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

#[derive(clap::Args, Debug)]
struct LintArgs {
    /// Config TOML path (rule toggles + severities; also supplies the replay
    /// state's `ttl_seconds` / `max_history`). Defaults to the built-in
    /// configuration.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
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

/// Load the config and validate every enabled rule's section, failing fast on a
/// malformed config. Shared by every subcommand; deliberately does **not**
/// initialize tracing (the proxy does that) so non-proxy commands like `lint`
/// keep stdout clean.
async fn load_validated_config(
    config_path: Option<&str>,
) -> anyhow::Result<std::sync::Arc<config::Config>> {
    let cfg = config::Config::load_or_builtin(config_path).await?;
    rules::validate_rules(&cfg)?;
    Ok(std::sync::Arc::new(cfg))
}

/// Load + validate the config and build the proxy's runtime inputs.
///
/// Proxy-specific: it initializes tracing and builds a `CaptureWriter`. Takes the
/// config *path* rather than the parsed CLI struct, so the proxy entry points are
/// decoupled from the command surface.
async fn load_and_prepare(
    config_path: Option<&str>,
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
async fn run_app(config_path: Option<&str>) -> anyhow::Result<()> {
    let (addr, capture_writer, cfg) = load_and_prepare(config_path).await?;
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
    let (addr, capture_writer, cfg) = load_and_prepare(config_path).await?;
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

/// Replay records through the rules — the shared core of `lint-captures` and
/// `run`.
///
/// Split out so the two commands cannot drift: `run` is not a second linter, it
/// is `lint-captures` pointed at a file the run just produced. Anything true of
/// one report is true of the other because there is one function that builds
/// them.
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
        // Lowercased and compared whole rather than sliced at an offset taken
        // from the scope's length: that offset is a byte index into a string
        // this does not control, and an internationalized host would land it
        // mid-character and panic.
        let host = host.to_ascii_lowercase();
        self.hosts.iter().any(|scope| {
            let scope = scope.to_ascii_lowercase();
            host == scope || host.ends_with(&format!(".{scope}"))
        })
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
            let included = match &block {
                FindingsBlock::HttpTransaction(f) => self.includes(&f.uri),
                // A WebSocket session is always kept: it exists because an
                // upgrade was made deliberately, and its record carries no
                // target to compare anyway.
                FindingsBlock::WebsocketSession(_) => true,
            };
            if included {
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
    let after_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
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

/// Render the `lint` report: the text form ends with a human summary line
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
            use std::fmt::Write;
            let mut out = String::new();
            for block in findings {
                out.push_str(&render_findings_block(block)?);
            }
            let total: usize = findings.iter().map(|f| f.violations().len()).sum();
            write!(
                out,
                "\n{total} violation(s) in {transaction_count} transaction(s)"
            )?;
            if websocket_count > 0 {
                write!(out, " and {websocket_count} websocket session(s)")?;
            }
            out.push('\n');
            Ok(out)
        }
    }
}

/// Wrap one command: stand a proxy up for it, run it, report what crossed.
///
/// The exit code is the child's unless `--fail-on` says otherwise, so putting
/// `lint-http run --` in front of a command does not change what that command's
/// success means. The report goes to stderr because stdout belongs to the child.
async fn run_wrapped(args: RunArgs) -> anyhow::Result<u8> {
    let cfg = load_validated_config(args.config.as_deref()).await?;

    // `--print-env` answers "what would this do to my environment" without
    // doing it, so it needs no child and reports against a placeholder address.
    if args.print_env {
        write_stdout(&render_env_preview())?;
        return Ok(0);
    }

    let Some((program, rest)) = args.command.split_first() else {
        anyhow::bail!("no command given; try `lint-http run -- curl https://example.com`");
    };

    let run = proxied_run::run_proxied(
        (*cfg).clone(),
        program,
        rest,
        args.captures.as_deref().map(std::path::Path::new),
    )
    .await?;

    let min_severity: lint::Severity = args.min_severity.into();
    let report = lint_records(&cfg, run.records, min_severity)?;
    write_stderr(&render_lint_report(
        &report.findings,
        report.transaction_count,
        report.websocket_count,
        args.format,
    )?)?;

    // The child's code is the run's, and it is *not* overridden by a clean lint
    // — a passing test suite that also happens to be tidy still exits 0, and a
    // failing one still exits non-zero whatever the findings said.
    let child_code = run.exit_code.unwrap_or(1);
    let Some(fail_on) = args.fail_on else {
        return Ok(u8::try_from(child_code).unwrap_or(1));
    };
    // With `--fail-on`, a finding at that severity fails the run — but a child
    // that already failed keeps its own code, which is the more specific answer.
    let fail_on: lint::Severity = fail_on.into();
    let tripped = report
        .findings
        .iter()
        .flat_map(|f| f.violations())
        .any(|v| v.severity >= fail_on);
    if child_code != 0 {
        return Ok(u8::try_from(child_code).unwrap_or(1));
    }
    Ok(if tripped { 1 } else { 0 })
}

/// The environment `run` would add, rendered for a human.
///
/// The address and path are placeholders — every real run picks a fresh port
/// and a fresh temporary CA — so this answers *which* variables are set and
/// who reads them, which is the question someone debugging an unwrapped client
/// is actually asking.
fn render_env_preview() -> String {
    use std::fmt::Write;
    let mut out = String::new();
    out.push_str("# Set for the wrapped command. The port and CA path are per-run.\n");
    for var in client_env::CLIENT_ENV {
        let value = match var.value {
            client_env::EnvValue::ProxyUrl => "http://127.0.0.1:<port>",
            client_env::EnvValue::CaFile => "<tmp>/ca.crt",
        };
        let _ = writeln!(out, "{:<20} {:<24} # {}", var.name, value, var.reads);
    }
    out
}

/// Open a browser against a session proxy and report what it fetches.
///
/// Unlike `run`, findings are printed as they commit. A browsing session lasts
/// as long as someone keeps it open and makes hundreds of requests; holding
/// everything until the window closes would deliver the report after the thing
/// it describes is gone. `--format json` opts back into one report at the end,
/// because a machine reading this wants one document rather than a stream.
async fn browse(args: BrowseArgs) -> anyhow::Result<u8> {
    let cfg = load_validated_config(args.config.as_deref()).await?;
    let browser = browser::discover(args.browser.as_deref())?;

    // The scope, decided before anything opens so it can be reported.
    let scope = if args.all_hosts {
        HostScope::all()
    } else if !args.only_host.is_empty() {
        HostScope {
            hosts: args.only_host.clone(),
        }
    } else {
        // The first party is the host being opened. With no URL there is none
        // to infer, and narrowing to nothing would report nothing.
        match args.url.as_deref().and_then(uri_host) {
            Some(host) => HostScope {
                hosts: vec![host.to_string()],
            },
            None => HostScope::all(),
        }
    };

    let session = proxied_run::ProxySession::start(
        (*cfg).clone(),
        args.captures.as_deref().map(std::path::Path::new),
    )
    .await?;

    let pin = session.spki_pin().await?;
    if pin.is_none() {
        eprintln!(
            "warning: no interception CA; HTTPS will be tunnelled unlinted and only plaintext is reported"
        );
    }

    let profile = session.scratch("browser-profile");
    std::fs::create_dir_all(&profile)?;

    eprintln!(
        "{} through 127.0.0.1:{}{}",
        browser.name,
        session.addr.port(),
        match &scope.hosts[..] {
            [] => " — reporting every host".to_string(),
            hosts => format!(" — reporting {}", hosts.join(", ")),
        }
    );

    // Text mode narrates; JSON mode stays silent so its one document is the
    // only thing on the stream a machine is reading.
    let live = matches!(args.format, OutputFormat::Text).then(|| {
        tokio::spawn(live_reporter(
            session.subscribe(),
            scope.clone(),
            args.min_severity.into(),
        ))
    });

    let command = browser::command(
        &browser,
        &profile,
        session.addr,
        pin.as_deref(),
        args.url.as_deref(),
    );
    // A failure to launch is still an error and propagates; an interrupt is not,
    // because closing a browser with Ctrl-C is how a browsing session ordinarily
    // ends. Distinguishing them is why `await_child` returns a `ChildOutcome`.
    let outcome = proxied_run::await_child(spawn_browser(command)).await?;

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

    // Counted before the replay consumes the records, because the summary has
    // to divide like with like: a scoped violation count over an unscoped
    // transaction count reads as "3 violation(s) in 480 transaction(s)" when
    // 472 of those were never in the report's scope at all.
    let in_scope_transactions = records
        .iter()
        .filter(|record| match record {
            capture::CaptureRecord::HttpTransaction(tx) => scope.includes(&tx.request.uri),
            capture::CaptureRecord::WebsocketSession(_) => false,
        })
        .count();

    let report = lint_records(&cfg, records, args.min_severity.into())?;
    let (findings, elsewhere) = scope.apply(report.findings);
    let total: usize = findings.iter().map(|f| f.violations().len()).sum();

    match args.format {
        OutputFormat::Json => {
            write_stdout(&render_lint_report(
                &findings,
                report.transaction_count,
                report.websocket_count,
                OutputFormat::Json,
            )?)?;
        }
        OutputFormat::Text => {
            // The blocks were printed live; only the tally is new.
            let mut summary =
                format!("\n{total} violation(s) in {in_scope_transactions} transaction(s)");
            if report.websocket_count > 0 {
                summary.push_str(&format!(
                    " and {} websocket session(s)",
                    report.websocket_count
                ));
            }
            if elsewhere > 0 {
                // Said rather than silently dropped: a reader has to be able to
                // tell "clean" from "scoped away from the mess". The other
                // transaction count goes with it, so both halves of the session
                // are accounted for.
                let others = report
                    .transaction_count
                    .saturating_sub(in_scope_transactions);
                summary.push_str(&format!(
                    "\n{elsewhere} more violation(s) in {others} transaction(s) on other hosts, not shown (--all-hosts)"
                ));
            }
            summary.push('\n');
            write_stderr(&summary)?;
        }
    }

    Ok(u8::try_from(exit).unwrap_or(0))
}

/// Run the browser, mapping a failure to launch onto a message that names it.
async fn spawn_browser(
    mut command: tokio::process::Command,
) -> anyhow::Result<std::process::ExitStatus> {
    let program = command
        .as_std()
        .get_program()
        .to_string_lossy()
        .into_owned();
    command
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run `{program}`: {e}"))
}

/// Print findings as their transactions commit.
///
/// Reads the live capture feed rather than replaying: the proxy has already run
/// the rules over each transaction by the time it writes one, so the findings
/// are there to be printed and re-linting them would be work done twice to
/// reach the same answer. The end-of-session report replays anyway, which is
/// what makes the summary authoritative.
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

        let gate = |violations: &[lint::Violation]| -> Vec<lint::Violation> {
            violations
                .iter()
                .filter(|v| v.severity >= min_severity)
                .cloned()
                .collect()
        };

        // Both record kinds, because both reach the summary. A WebSocket
        // session that was only counted and never printed would show up as a
        // number with nothing behind it — it commits once, when the session
        // ends, which is exactly when there is something to say about it.
        let block = match &envelope.record {
            capture::CaptureRecord::HttpTransaction(tx) => {
                if !scope.includes(&tx.request.uri) {
                    continue;
                }
                let violations = gate(&tx.violations);
                if violations.is_empty() {
                    continue;
                }
                FindingsBlock::HttpTransaction(TransactionFindings {
                    method: tx.request.method.clone(),
                    uri: tx.request.uri.clone(),
                    status: tx.response.as_ref().map(|r| r.status),
                    violations,
                })
            }
            capture::CaptureRecord::WebsocketSession(session) => {
                // Never scoped away: the record carries no target to compare,
                // and `HostScope::apply` keeps it for the same reason.
                let violations = gate(&session.violations);
                if violations.is_empty() {
                    continue;
                }
                FindingsBlock::WebsocketSession(WebsocketFindings {
                    session_id: session.id,
                    transaction_id: session.transaction_id,
                    close_code: session.close_code,
                    violations,
                })
            }
        };
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
    match cli.command {
        Some(Command::Run(args)) => run_wrapped(args).await,
        Some(Command::Browse(args)) => browse(args).await,
        Some(Command::ProxyStart(args)) => {
            run_app(args.config.as_deref()).await?;
            Ok(0)
        }
        // Non-zero exit when findings exist, so CI fails on a dirty capture;
        // real errors (bad config / missing file) still bubble up as `Err`.
        Some(Command::LintCaptures(args)) => {
            let found = lint_app(
                args.config.as_deref(),
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
                    Some(path) => Some(load_validated_config(Some(path)).await?),
                    None => None,
                };
                write_stdout(&rules_list(a.format, cfg.as_deref())?)?;
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
    use clap::Parser;
    use tokio::fs;
    use uuid::Uuid;

    #[test]
    fn cli_proxy_start_parses_config() {
        let cli = Cli::parse_from(["lint-http", "proxy-start", "--config", "x.toml"]);
        match cli.command {
            Some(Command::ProxyStart(args)) => assert_eq!(args.config.as_deref(), Some("x.toml")),
            other => panic!("expected ProxyStart, got {other:?}"),
        }
    }

    /// Every command that takes one may omit it, which is what makes the
    /// built-in configuration reachable without a file on disk.
    #[test]
    fn config_is_optional_everywhere_it_is_accepted() {
        match Cli::parse_from(["lint-http", "proxy-start"]).command {
            Some(Command::ProxyStart(args)) => assert!(args.config.is_none()),
            other => panic!("expected ProxyStart, got {other:?}"),
        }
        match Cli::parse_from(["lint-http", "lint-captures", "caps.jsonl"]).command {
            Some(Command::LintCaptures(args)) => assert!(args.config.is_none()),
            other => panic!("expected LintCaptures, got {other:?}"),
        }
        match Cli::parse_from(["lint-http", "run", "--", "true"]).command {
            Some(Command::Run(args)) => assert!(args.config.is_none()),
            other => panic!("expected Run, got {other:?}"),
        }
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
        match cli.command {
            Some(Command::LintCaptures(args)) => {
                assert_eq!(args.config.as_deref(), Some("c.toml"));
                assert_eq!(args.captures, "caps.jsonl");
            }
            other => panic!("expected LintCaptures, got {other:?}"),
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
        match cli.command {
            Some(Command::Run(args)) => {
                assert!(args.config.is_none(), "--config after -- is the child's");
                assert!(matches!(args.min_severity, SeverityArg::Warn));
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
            Some(Command::Run(args)) => assert!(args.fail_on.is_none()),
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
        match cli.command {
            Some(Command::LintCaptures(args)) => {
                assert!(matches!(args.format, OutputFormat::Json));
                assert!(matches!(args.min_severity, SeverityArg::Warn));
            }
            other => panic!("expected LintCaptures, got {other:?}"),
        }
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
        match cli.command {
            Some(Command::LintCaptures(args)) => {
                assert!(matches!(args.format, OutputFormat::Text));
                assert!(matches!(args.min_severity, SeverityArg::Info));
            }
            other => panic!("expected LintCaptures, got {other:?}"),
        }
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
    #[test]
    fn bare_config_is_no_longer_accepted() {
        assert!(Cli::try_parse_from(["lint-http", "--config", "x.toml"]).is_err());
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

    #[test]
    fn cli_browse_defaults_scope_to_the_url_host() {
        match Cli::parse_from(["lint-http", "browse", "https://example.com/app"]).command {
            Some(Command::Browse(args)) => {
                assert!(args.only_host.is_empty());
                assert!(!args.all_hosts);
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
        let result = run_app(Some(config_path)).await;

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
        let res = run_app(Some(config_path)).await;
        assert!(res.is_err());

        // Cleanup
        drop(l);
        Ok(())
    }
}
