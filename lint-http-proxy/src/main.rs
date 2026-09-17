// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

// The binary is its own compilation unit, so it includes the guard again —
// the same file, not a second copy of it. See the note in `lib.rs`.
#[cfg(test)]
#[path = "../tests/common/temp_files.rs"]
mod temp_files;

// A module of the binary and not of the library: nothing in it is about HTTP,
// and nothing that lints wants to know whether stderr is a terminal.
mod style;

use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

use lint_http::{
    capture, client_env, config, driver, engine, lint, protocol_event_store, proxied_run, proxy,
    rules, state, violations,
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
#[derive(clap::Args, Debug, Clone, Default)]
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
    /// Only report findings the named peer is answerable for. `any` reports
    /// every finding and is the default. A finding no rule has attributed yet
    /// is kept whichever peer is named, and counted on its own line.
    #[arg(long, value_enum, value_name = "PARTY", global = true)]
    about: Option<AboutArg>,
    /// The JSONL capture file this command reads or writes: where `run`,
    /// `use` and `proxy-start` write captures, and what `lint-captures`
    /// reads. Without it, `run` and `use` discard theirs.
    #[arg(long, value_name = "PATH", global = true)]
    captures: Option<String>,
    /// When to colour the report: `auto` (a terminal, unless `NO_COLOR`),
    /// `always`, `never`.
    #[arg(long, value_enum, value_name = "WHEN", global = true)]
    color: Option<style::ColorChoice>,
    /// Wrap the report at this column. Defaults to `COLUMNS`, then to 100 on a
    /// terminal; a report that is not going to one is never wrapped.
    #[arg(long, value_name = "COLUMNS", global = true)]
    width: Option<usize>,
    /// One line per defect: its catalogue title and how often it happened.
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Everything a finding knows: the rule that reported it, the
    /// specification reference in full, the docs page, and how to switch it off.
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    /// Show one entry per defect with a count and the targets it happened on,
    /// instead of one entry per transaction.
    #[arg(long, global = true)]
    group: bool,
}

/// Which stream a report is about to be written to.
///
/// Named rather than passed as a bool because the two commands disagree and
/// the disagreement is easy to get backwards: a session's text report goes to
/// stderr (stdout belongs to the child it wrapped), and `lint-captures` writes
/// to stdout. Asking the wrong one is how escape sequences end up in a file.
#[derive(Clone, Copy, Debug)]
enum Stream {
    Stdout,
    Stderr,
}

fn is_terminal(stream: Stream) -> bool {
    use std::io::IsTerminal;
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
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

    /// Which peer the report is about. Unnarrowed when nobody said, on the same
    /// argument [`format`](GlobalArgs::format) makes about applying a default
    /// at the point of use.
    fn about(&self) -> AboutScope {
        match self.about {
            Some(AboutArg::Client) => AboutScope {
                party: Some(lint::Party::Client),
            },
            Some(AboutArg::Server) => AboutScope {
                party: Some(lint::Party::Server),
            },
            Some(AboutArg::Any) | None => AboutScope::all(),
        }
    }

    fn captures_path(&self) -> Option<&std::path::Path> {
        self.captures.as_deref().map(std::path::Path::new)
    }

    /// The tier `-q` / `-v` selected. Neither is normal, and clap has already
    /// refused both at once.
    fn detail(&self) -> Detail {
        match (self.quiet, self.verbose) {
            (true, _) => Detail::Brief,
            (_, true) => Detail::Full,
            _ => Detail::Normal,
        }
    }

    /// How this report is drawn, given what the stream it is headed for turned
    /// out to be.
    fn render_opts(&self, is_tty: bool) -> RenderOpts {
        let styles = style::Styles::new(self.color.unwrap_or_default().resolve(is_tty));
        RenderOpts {
            styles,
            detail: self.detail(),
            wrap: self.wrap(is_tty),
            group: self.group,
        }
    }

    /// The column to wrap at, or `None` for the single-line shape.
    ///
    /// **There is no width probe here, and that is a decision.** Reading a
    /// terminal's size means either an `ioctl` — which this workspace denies
    /// outright, `unsafe_code = "deny"`, and a linter is the last place to
    /// spend that budget — or a crate that does one, which is a supply-chain
    /// entry bought for a cosmetic. So the width is *stated* rather than
    /// discovered: `--width` if given, then `COLUMNS` if the shell exported
    /// it, then a conservative 100. A report that is not going to a terminal
    /// is never wrapped, whatever any of them said, because the only reader
    /// there is another program.
    fn wrap(&self, is_tty: bool) -> Option<usize> {
        if let Some(width) = self.width {
            return (width > 0).then_some(width);
        }
        if !is_tty {
            return None;
        }
        Some(
            std::env::var("COLUMNS")
                .ok()
                .and_then(|c| c.trim().parse::<usize>().ok())
                // Floored rather than discarded: a 30-column terminal is
                // narrow, and answering it with 100 wraps to a width wider
                // than the thing being measured. `--width` is taken literally
                // above, because there a person said the number.
                .map(|w| w.max(40))
                .unwrap_or(100),
        )
    }
}

/// The command surface, named for how often each is reached for.
///
/// `run` is the short name because wrapping one command is the thing a person
/// does dozens of times a day; `proxy-start` is the long one because standing a
/// proxy up and configuring a client to use it is a session you begin once and
/// leave running. The names were the other way round, which had the frequent
/// case spelling out a config path and the rare case spelled `run`.
///
/// `run` and `use` are siblings and neither replaces the other: `run --` is
/// tool-blind and works on anything, `use` knows the tool and configures it the
/// way the tool documents. `browse` used to be a third, and was `use browser`
/// all along.
#[derive(Subcommand, Debug)]
enum Command {
    /// Run a command with its HTTP traffic proxied and linted.
    Run(RunArgs),
    /// Drive a tool this knows how to configure, and lint its traffic.
    Use(UseArgs),
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

/// `lint-http use <TOOL> [ARGS]...`
///
/// The sibling of `run`, and the difference is one word: `run --` hands a
/// command an environment and hopes it reads it; `use` reads the tool's own
/// arguments and configures it the way that tool documents. `run` stays, and is
/// what to reach for when nothing here drives the tool.
///
/// `browse` was this command before it was general — a browsing session against
/// a proxy that exists only for it, with a throwaway profile and a CA trusted
/// for one launch by public-key pin. It is `use browser` now, and everything it
/// could do that `run` could not — scoping a report to the site under test,
/// printing findings as they happen, refusing the switch that would make every
/// TLS finding meaningless — is a driver's answer rather than one command's
/// private feature.
///
/// **lint-http's own options go before the tool.** Everything after it belongs
/// to the tool, which is what makes an unknown flag safe to type: it is passed
/// through rather than rejected. Same rule as `run`'s `--`, one word earlier.
#[derive(clap::Args, Debug)]
struct UseArgs {
    /// The tool to drive — a name it answers to (`curl`, `browser`, `chrome`)
    /// or a path to the executable — then the tool's own arguments, which are
    /// passed through.
    // One list rather than a name and a list, because that is what makes the
    // passthrough hold: `trailing_var_arg` starts at the *first* value, so a
    // separate positional for the name would leave `use curl --fail-on error`
    // parsing `--fail-on` as lint-http's.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "TOOL"
    )]
    command: Vec<String>,
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
    /// `targets` is what the session was pointed at, when the command knows —
    /// the URLs a browser was opened on, or the ones a driver read out of the
    /// tool's own arguments. They are the default first parties, because a
    /// report about a page is about that page and not about the eleven CDNs it
    /// reaches. `run --` knows no target, so it reports everything, which is
    /// what it always did.
    ///
    /// All of them, not the first: `curl https://a/ https://b/` is one
    /// invocation of two hosts, and scoping to `a` would drop `b` from the
    /// report without saying so.
    fn scope(&self, targets: &[String]) -> HostScope {
        if self.all_hosts {
            return HostScope::all();
        }
        if !self.only_host.is_empty() {
            return HostScope::new(self.only_host.clone());
        }
        // Narrowing to nothing would report nothing, so targets this cannot
        // read widen rather than narrow.
        let hosts: Vec<String> = targets
            .iter()
            .filter_map(|target| uri_host(target))
            .map(str::to_string)
            .collect();
        if hosts.is_empty() {
            return HostScope::all();
        }
        HostScope::new(hosts)
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
/// and `use` write is what this reads. Naming it twice is an error rather
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

/// The CLI's mirror of [`lint::Party`], plus the `any` that is the absence of a
/// filter — the shape [`SeverityArg`] has, for the same reason: `lint` does not
/// know clap, and `any` is not a party.
///
/// `Neither` is deliberately not spellable. It is an answer a *rule* gives about
/// a defect that lives in the exchange, and a reader asking to see what their
/// client is answerable for wants those too; a flag value for it would offer to
/// narrow a report to findings nobody can act on alone.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum AboutArg {
    Client,
    Server,
    Any,
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
/// rename `run` and the browsing session ran a proxy through a different
/// function and silently discarded every diagnostic it produced.
///
/// **That combination is the one that makes this tool lie.** They
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
    // `run` and `use` belongs to the wrapped command — so the default would
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
fn rules_list(
    format: OutputFormat,
    cfg: Option<&config::Config>,
    styles: style::Styles,
) -> anyhow::Result<String> {
    let infos = collect_rule_info(cfg);
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&infos)?),
        OutputFormat::Text => {
            use std::fmt::Write;
            let mut out = String::new();
            for info in &infos {
                // Padded on the plain id and painted afterwards: an escape
                // sequence takes no columns on screen and every column in a
                // `{:<60}`, so styling first would ragged every line by
                // exactly the width of its own colour.
                write!(
                    out,
                    "{}",
                    styles.paint(styles.name(), &format!("{:<60}", info.id))
                )?;
                if let Some(enabled) = info.enabled {
                    let state = format!("{:<8}", if enabled { "enabled" } else { "disabled" });
                    // A disabled rule recedes; an enabled one is the ordinary
                    // case and takes no marking at all.
                    let state = if enabled {
                        state
                    } else {
                        styles.paint(styles.dim(), &state)
                    };
                    write!(out, " {state}")?;
                }
                // Most rules have no title override; omit the field entirely so
                // those lines don't carry a trailing space.
                let scope = styles.paint(styles.dim(), &format!("[{}]", info.scope));
                match info.title {
                    Some(title) => writeln!(out, " {scope} {title}")?,
                    None => writeln!(out, " {scope}")?,
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
    global: &GlobalArgs,
) -> anyhow::Result<usize> {
    let format = global.format();
    let min_severity = global.min_severity();
    // This report is the command's output, so it goes to stdout — unlike a
    // session's, which yields stdout to the child it wrapped. Colour follows
    // the stream that is actually written to.
    let opts = global.render_opts(is_terminal(Stream::Stdout));
    let cfg = load_validated_config(config_path).await?;
    // `load_capture_records` tolerates a missing file (it backs the proxy's
    // optional cold-start seeding). For an explicit `lint-captures <file>` a
    // missing path is a user error — fail loudly rather than letting CI pass
    // green on a typo'd path.
    if !tokio::fs::try_exists(captures_path).await.unwrap_or(false) {
        anyhow::bail!("capture file not found: {captures_path}");
    }
    let records = capture::load_capture_records(captures_path).await?;
    let report = lint_records(&cfg, records, min_severity, global.about())?;
    let total = report.total();
    let summary = Summary {
        hidden_severity: report.suppressed,
        min_severity,
        hidden_party: report.hidden_party,
        about: global.about(),
        unattributed: report.unattributed,
        ..Summary::counted(
            &report.findings,
            report.transaction_count,
            report.websocket_count,
        )
    };
    write_stdout(&render_lint_report(
        &report.findings,
        &summary,
        format,
        opts,
    )?)?;
    Ok(total)
}

/// The findings of one replay, with the counts the summary line needs.
struct LintReport {
    findings: Vec<FindingsBlock>,
    transaction_count: usize,
    websocket_count: usize,
    /// Findings `--min-severity` removed before the report existed.
    ///
    /// Counted rather than merely dropped, because a filtered report and a
    /// clean one are indistinguishable otherwise — and the flag that would
    /// show them is the one thing the reader needs to be told.
    suppressed: usize,
    /// Findings `--about` removed because the other peer is answerable for
    /// them. A second cause needs a second number for the same reason the
    /// first one did.
    hidden_party: usize,
    /// Findings `--about` kept for want of an answer. Not a hidden count and
    /// not rendered as one: the report is showing them.
    unattributed: usize,
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
/// What the report-wide filters removed from one record's findings, and what
/// they let through without being able to measure it.
///
/// Returned rather than accumulated in place because the two callers own their
/// findings differently — one clones out of a borrowed record, the other moves
/// out of an owned one — and the arithmetic is the half they must agree on.
#[derive(Debug, Default, Clone, Copy)]
struct Removed {
    suppressed: usize,
    hidden_party: usize,
    unattributed: usize,
}

impl Removed {
    fn add(&mut self, other: Self) {
        self.suppressed += other.suppressed;
        self.hidden_party += other.hidden_party;
        self.unattributed += other.unattributed;
    }
}

/// Drop from `violations` everything the report-wide filters exclude, and say
/// what went and why.
///
/// **One function, because there are two paths and they must not disagree.**
/// `gated_block` reads findings off a record the live pass already made;
/// `lint_records` re-lints a capture and used to spell the severity retain out
/// a second time, inline. A second filter arriving in one of them and not the
/// other is the drift [`gated_block`] was extracted to prevent, one level down.
///
/// **Severity first, then peer**, and the order is what keeps the numbers
/// meaning what they say: a finding below the gate was never in the report for
/// `--about` to have an opinion about, so it is counted once and not twice.
fn retain_reportable(
    violations: &mut Vec<lint::Violation>,
    min_severity: lint::Severity,
    about: AboutScope,
) -> Removed {
    let mut removed = Removed::default();
    violations.retain(|v| {
        if v.severity < min_severity {
            removed.suppressed += 1;
            return false;
        }
        if !about.includes(v) {
            removed.hidden_party += 1;
            return false;
        }
        // Kept, and counted: this one survived a narrowing it could not be
        // measured against, which is the catalogue's incompleteness rather than
        // the traffic's. Only worth counting when something was narrowing.
        if !about.is_all() && v.party.is_none() {
            removed.unattributed += 1;
        }
        true
    });
    removed
}

fn gated_block(
    record: &capture::CaptureRecord,
    min_severity: lint::Severity,
    about: AboutScope,
) -> Gated {
    let mut removed = Removed::default();
    let mut gate = |violations: &[lint::Violation]| -> (Vec<lint::Violation>, usize) {
        let mut kept = violations.to_vec();
        removed.add(retain_reportable(&mut kept, min_severity, about));
        let suppressed = removed.suppressed;
        (kept, suppressed)
    };
    match record {
        capture::CaptureRecord::HttpTransaction(tx) => {
            let (violations, suppressed) = gate(&tx.violations);
            Gated {
                block: (!violations.is_empty()).then(|| {
                    FindingsBlock::HttpTransaction(TransactionFindings {
                        method: tx.request.method.clone(),
                        uri: tx.request.uri.clone(),
                        status: tx.response.as_ref().map(|r| r.status),
                        violations,
                    })
                }),
                suppressed,
                hidden_party: removed.hidden_party,
                unattributed: removed.unattributed,
            }
        }
        capture::CaptureRecord::WebsocketSession(session) => {
            let (violations, suppressed) = gate(&session.violations);
            Gated {
                block: (!violations.is_empty()).then_some(FindingsBlock::WebsocketSession(
                    WebsocketFindings {
                        session_id: session.id,
                        transaction_id: session.transaction_id,
                        close_code: session.close_code,
                        violations,
                    },
                )),
                suppressed,
                hidden_party: removed.hidden_party,
                unattributed: removed.unattributed,
            }
        }
    }
}

/// One record after the severity gate: what survived, and how much did not.
///
/// The second half is not bookkeeping. A report narrowed by `--min-severity`
/// and a report with nothing to say print the same closing line unless
/// somebody counted what the gate removed, and "clean" and "filtered" are the
/// two answers a reader most needs told apart.
struct Gated {
    block: Option<FindingsBlock>,
    suppressed: usize,
    /// Findings the other peer is answerable for, dropped by `--about`.
    hidden_party: usize,
    /// Findings kept *despite* `--about`, because nothing says whose they are.
    /// Zero when the report was not narrowed, since a number nobody could act
    /// on is not worth a line.
    unattributed: usize,
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
    about: AboutScope,
) -> LintReport {
    let mut findings = Vec::new();
    let mut tx_count = 0usize;
    let mut ws_count = 0usize;
    let mut suppressed = 0usize;
    let mut hidden_party = 0usize;
    let mut unattributed = 0usize;
    for record in records {
        match record {
            capture::CaptureRecord::HttpTransaction(_) => tx_count += 1,
            capture::CaptureRecord::WebsocketSession(_) => ws_count += 1,
        }
        let gated = gated_block(record, min_severity, about);
        suppressed += gated.suppressed;
        hidden_party += gated.hidden_party;
        unattributed += gated.unattributed;
        findings.extend(gated.block);
    }
    LintReport {
        findings,
        transaction_count: tx_count,
        websocket_count: ws_count,
        suppressed,
        hidden_party,
        unattributed,
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
    about: AboutScope,
) -> anyhow::Result<LintReport> {
    let state = state::StateStore::new(cfg.general.ttl_seconds, cfg.general.max_history);
    // Precompute the enabled rule set once, then reuse it across the replay.
    let engine = engine::PreparedEngine::new(cfg)?;

    let mut findings = Vec::new();
    let mut tx_count = 0usize;
    let mut ws_count = 0usize;
    let mut removed = Removed::default();
    for record in records {
        match record {
            capture::CaptureRecord::HttpTransaction(tx) => {
                tx_count += 1;
                let mut violations = engine.lint_transaction(&tx, &state);
                // Record *before* gating: stateful rules must see every
                // transaction in the file regardless of what the report includes.
                state.record_transaction(&tx);
                removed.add(retain_reportable(&mut violations, min_severity, about));
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
                removed.add(retain_reportable(&mut violations, min_severity, about));
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
        suppressed: removed.suppressed,
        hidden_party: removed.hidden_party,
        unattributed: removed.unattributed,
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

    /// Keep only the findings a predicate accepts. The live pass uses it to
    /// drop what a collapsed report has already shown once.
    fn retain_violations(&mut self, keep: impl FnMut(&lint::Violation) -> bool) {
        match self {
            FindingsBlock::HttpTransaction(f) => f.violations.retain(keep),
            FindingsBlock::WebsocketSession(f) => f.violations.retain(keep),
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

/// Which peer a report is about.
///
/// **The other half of what makes a session's report readable.** [`HostScope`]
/// answers *whose traffic*, and a report scoped to one host is still every
/// finding about both ends of it — a client author reading a wall of
/// `Cache-Control` advice about somebody else's origin, a server author reading
/// their own `User-Agent`. This answers *which end*, and the two compose: host
/// first, then peer.
///
/// `None` means every peer, which is what `--about any` selects and what a
/// report nobody narrowed falls back to.
#[derive(Debug, Clone, Copy, Default)]
struct AboutScope {
    party: Option<lint::Party>,
}

impl AboutScope {
    fn all() -> Self {
        Self::default()
    }

    fn is_all(&self) -> bool {
        self.party.is_none()
    }

    /// Does this report include the given finding?
    ///
    /// **A finding nobody has attributed is kept, whichever peer is named**, and
    /// that is the same decision [`HostScope::includes`] makes about a target it
    /// cannot parse, in the same words: the alternative is dropping a finding
    /// for a reason the user cannot see. Here the reason would be worse than
    /// invisible — it would be the catalogue's own incompleteness, reported as
    /// if it were a fact about the traffic.
    ///
    /// It also matters that `--fail-on` reads the filtered report. Hiding what
    /// is not yet attributed would turn an unread rule into a green build, and
    /// a false negative through a gate is the one failure this tool cannot
    /// have. Keeping produces a false positive instead, which is visible,
    /// actionable, and shrinks to nothing as the catalogue is read.
    ///
    /// [`Party::Neither`](lint::Party::Neither) is kept for both peers too, and
    /// for a different reason: it is a decided answer that the defect is in the
    /// exchange, so it is a finding *either* reader may have to act on.
    fn includes(&self, violation: &lint::Violation) -> bool {
        let Some(party) = self.party else {
            return true;
        };
        match violation.party {
            None | Some(lint::Party::Neither) => true,
            Some(named) => named == party,
        }
    }
}

/// Which hosts a report is about.
///
/// **A browsing session is unusable without this.** One real page pulls in tens of
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

/// How much of a finding a report draws.
///
/// Three tiers, and the top and bottom of the range are made of data the
/// binary already carried and never printed. The catalogue holds a one-line
/// `title` per defect written to be read out of context, and a `spec` list
/// whose notes say what each reference contributes; the report showed neither
/// and the long parameterised `message` always.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Detail {
    /// `-q`: one line per defect — its catalogue title and how often it
    /// happened. No message, no citation, no request lines.
    Brief,
    /// The message, and the citation as a label.
    #[default]
    Normal,
    /// `-v`: the rule that reported it, the specification reference in full
    /// with the note that says what it contributes, the documentation page,
    /// and the stanza that switches it off.
    Full,
}

/// The choices a *reader* makes about a report, as against the findings in it.
///
/// Threaded through every renderer rather than read from a global, and carried
/// as data rather than applied to the stream, because every function below
/// returns a `String` that a test asserts on. A writer that styled its own
/// bytes would put the decision somewhere no test can see, and would style the
/// JSON document and the diagnostics along with the report.
#[derive(Clone, Copy, Debug, Default)]
struct RenderOpts {
    styles: style::Styles,
    detail: Detail,
    /// Wrap the message at this column, or leave every finding on one line.
    ///
    /// `None` whenever the report is not going to a terminal, which is what
    /// keeps a piped report one line per finding — the shape `grep` and every
    /// script that has ever read this output expect. A terminal gets the
    /// wrapped shape, because at 300 characters the alternative is not a long
    /// line but three ragged ones with no indent.
    wrap: Option<usize>,
    /// Collapse findings that read identically into one entry with a count.
    group: bool,
}

impl RenderOpts {
    /// Unstyled, unwrapped, ungrouped, normal detail — what the tests assert
    /// against, and what a real run produces for a pipe by resolving each of
    /// those choices to the same answer. `#[cfg(test)]` because a real run
    /// always has a `GlobalArgs` to derive them from and must never take a
    /// short cut past `--color` and `--width`.
    #[cfg(test)]
    fn plain() -> Self {
        Self::default()
    }

    /// Does this report show one entry per defect rather than one per finding?
    ///
    /// `--group` asks for it outright; `-q` implies it, because a tier whose
    /// whole content is a title and a count has nothing to say a second time.
    fn collapse(&self) -> bool {
        self.group || self.detail == Detail::Brief
    }
}

/// `n` of something, with the plural the sentence actually needs.
///
/// `violation(s)` was one line of output and one of the few places this tool
/// wrote something no person would write. It is also, at `1 violation(s)`,
/// wrong twice.
fn plural(n: usize, singular: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {singular}s")
    }
}

/// Break `text` into lines no wider than `width`, each after `indent` spaces.
///
/// Words are never broken: a URL or a quoted field value longer than the
/// column overflows it rather than being cut in half, because half a URL is
/// worse than a long line — it cannot be clicked, copied, or recognised.
fn wrap_text(text: &str, indent: usize, width: usize) -> Vec<String> {
    let room = width.saturating_sub(indent).max(20);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= room {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Push `text` at `indent`, wrapped when the report has a width to wrap to.
fn push_wrapped(out: &mut String, text: &str, indent: usize, opts: RenderOpts) {
    let pad = " ".repeat(indent);
    match opts.wrap {
        Some(width) => {
            for line in wrap_text(text, indent, width) {
                out.push_str(&pad);
                out.push_str(&line);
                out.push('\n');
            }
        }
        None => {
            out.push_str(&pad);
            out.push_str(text);
            out.push('\n');
        }
    }
}

/// Shorten a target that will not fit, keeping both ends.
///
/// The head of a URI is the scheme and host and the tail is the resource; the
/// middle is the part a reader skims. Cutting from the end — the obvious
/// truncation — keeps the two least distinguishing halves and drops the one
/// that says *which* request this was.
fn elide_middle(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max || max < 8 {
        return text.to_string();
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let chars: Vec<char> = text.chars().collect();
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[count - tail..]);
    out
}

/// The name a finding goes by in the report.
///
/// The defect, when it names one. It is the unit of report — the name
/// `[violations.<id>]` tunes, the name `enabled = false` switches off, and the
/// name someone greps a capture for — while the rule is the unit of *analysis*
/// and answers a different question. Printing `rule/defect` on every line
/// spelled one stem twice while the eye was hunting for the difference between
/// them; the rule is still there, under `-v`, where "which analysis do I switch
/// off" is actually being asked.
fn violation_name(v: &lint::Violation) -> &str {
    if v.violation.is_empty() {
        &v.rule
    } else {
        &v.violation
    }
}

/// The catalogue's one-line name for this defect, for the tier that shows
/// nothing else.
///
/// Falls back to the message when the catalogue has no entry — a finding from
/// a rule that names no defect, or a capture written under an id since
/// renamed. Never to the id itself: the id is already on the line.
fn violation_title(v: &lint::Violation) -> String {
    violations::by_id(&v.violation)
        .map(|def| def.title.to_string())
        .unwrap_or_else(|| v.message.clone())
}

/// A citation as the report shows it.
///
/// **The compaction is paid for by the hyperlink.** Under colour the label
/// alone is printed and the URL rides along as an OSC 8 target, so
/// `RFC 9110 §12.5.3` is both 58 characters shorter than what it replaces and
/// still one click from the section. Where there is no colour there is no
/// hyperlink either, so the URL is printed exactly as it always was — a report
/// in a file must not lose the address of the sentence it enforces.
fn render_cite(cite: &lint::SpecCitation, opts: RenderOpts) -> String {
    let label = cite.label();
    if opts.styles.is_enabled() {
        opts.styles
            .paint(opts.styles.citation(), &opts.styles.link(&cite.url, &label))
    } else {
        format!("[{label} {}]", cite.url)
    }
}

/// The severity column: five characters wide, so the names line up under each
/// other whatever mix a report holds.
fn render_severity(severity: lint::Severity, opts: RenderOpts) -> String {
    opts.styles.paint(
        opts.styles.severity(severity),
        &format!("{:<5}", severity.name()),
    )
}

/// What `-v` adds under a finding: everything it knows that the line has no
/// room for.
///
/// Four labelled sub-lines, each answering a question the default report
/// leaves open — which analysis found this, what text it enforces, where to
/// read more, and how to make it stop.
fn render_violation_detail(v: &lint::Violation, indent: usize, opts: RenderOpts, out: &mut String) {
    let pad = " ".repeat(indent);
    let label = |name: &str| opts.styles.paint(opts.styles.dim(), name);

    out.push_str(&format!("{pad}{}  {}\n", label("rule"), v.rule));

    // **The catalogue is asked first, and it is asked for the whole reference.**
    // A finding carries a citation only when its defect has exactly one
    // governing statement, so reading the references off the *finding* leaves
    // the 19 defects that name two with nothing under `spec` — and their notes,
    // printed anyway, sitting indented under no heading at all.
    //
    // `note` is not a quotation. The verbatim sentence lives in the `// cite`
    // comment at the enforcing statement, where the quote gate checks it
    // against the published document; a second copy in a struct is a copy
    // nothing verifies. This is what the reference contributes to this defect.
    let def = violations::by_id(&v.violation);
    match def {
        Some(def) => {
            for spec in def.spec {
                let section = spec
                    .section
                    .map_or_else(|| spec.spec.to_string(), |s| format!("{} §{s}", spec.spec));
                out.push_str(&format!("{pad}{}  {section}\n", label("spec")));
                out.push_str(&format!("{pad}      {}\n", spec.url));
                if !spec.note.is_empty() {
                    push_wrapped(out, spec.note, indent + 6, opts);
                }
            }
        }
        // No catalogue entry — a finding from a rule that names no defect, or a
        // capture written under an id since renamed. What it carries is all
        // there is, and it is still worth printing.
        None => {
            if let Some(cite) = &v.cite {
                out.push_str(&format!("{pad}{}  {}\n", label("spec"), cite.label()));
                out.push_str(&format!("{pad}      {}\n", cite.url));
            }
        }
    }

    if let Some(def) = def {
        out.push_str(&format!(
            "{pad}{}  docs/violations/{}.md\n",
            label("docs"),
            def.id
        ));
        out.push_str(&format!(
            "{pad}{}  [violations.{}]\n{pad}      enabled = false\n",
            label("hush"),
            def.id
        ));
    }
}

/// One finding, drawn at whatever detail and width the report asked for.
///
/// Two shapes, and which one is used is decided by [`RenderOpts::wrap`] alone:
/// unwrapped it is the single line this tool has always printed, so a pipe
/// keeps one line per finding; wrapped, the name takes its own line and the
/// message is indented under it, because the alternative at a real terminal
/// width is the same line soft-wrapped into three rows with no indent at all,
/// which is the column structure destroying itself.
fn render_violation(v: &lint::Violation, opts: RenderOpts, out: &mut String) {
    let name = opts.styles.paint(opts.styles.name(), violation_name(v));
    let severity = render_severity(v.severity, opts);
    let cite = v.cite.as_ref().map(|c| render_cite(c, opts));
    // Beside the name, because it qualifies *which finding this is* rather than
    // what it says: the message is about a header the client wrote, and it is
    // true, and it would not be on the wire if this proxy were not. A reader
    // about to go hunting for the bug should be told before they read the
    // sentence, not after.
    let induced = if v.proxy_induced {
        format!(
            " {}",
            opts.styles
                .paint(opts.styles.dim(), "(induced by this proxy)")
        )
    } else {
        String::new()
    };

    if opts.wrap.is_none() && opts.detail != Detail::Full {
        out.push_str(&format!("  {severity} {name}{induced}  {}", v.message));
        if let Some(cite) = &cite {
            out.push_str("  ");
            out.push_str(cite);
        }
        out.push('\n');
        return;
    }

    out.push_str(&format!("  {severity} {name}{induced}\n"));
    push_wrapped(out, &v.message, 8, opts);
    if opts.detail == Detail::Full {
        // No citation line here: the `spec` sub-line below says the same thing
        // and more, and printing both would put the URL on screen twice under
        // the one tier that was asked for detail rather than for brevity.
        render_violation_detail(v, 8, opts, out);
    } else if let Some(cite) = &cite {
        // Its own line rather than the tail of the last one: the label is
        // styled and hyperlinked, so appending it would mean measuring a run
        // of text whose escapes take no columns, and getting that wrong shows
        // up as a line that wraps one word early on every cited finding.
        out.push_str(&format!("        {cite}\n"));
    }
}

/// One record's findings, as the text report prints them.
///
/// Extracted from [`render_lint_report`] so a session can print a block the
/// moment its transaction commits. A browsing session runs for minutes and
/// makes hundreds of requests; saving every finding for the end would be the
/// same output delivered when it is no longer about anything on screen. Same
/// function, so the live lines and a replayed report cannot disagree on shape.
fn render_findings_block(block: &FindingsBlock, opts: RenderOpts) -> anyhow::Result<String> {
    use std::fmt::Write;
    let mut out = String::new();
    match block {
        FindingsBlock::HttpTransaction(f) => {
            let status = f
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(
                out,
                "{} {} -> {}",
                opts.styles.paint(opts.styles.name(), &f.method),
                f.uri,
                opts.styles.paint(opts.styles.status(f.status), &status)
            )?;
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
        render_violation(v, opts, &mut out);
    }
    Ok(out)
}

/// One defect, and everywhere it happened.
///
/// **Grouping is not deduplication, and the difference is the count.** An
/// earlier attempt to drop repeated findings was abandoned because its key
/// could not tell one finding reported twice from two findings that read
/// alike, and dropping either is a lie. Nothing is dropped here: every finding
/// is still in the total, the count says how many there were, and the targets
/// say where — so two findings that read alike are visible as two, on two
/// lines, under one heading.
struct Group<'a> {
    severity: lint::Severity,
    violation: &'a lint::Violation,
    count: usize,
    /// Where it happened, in order of first appearance, each with its own
    /// count. A defect on one URL fetched ten times and a defect on ten URLs
    /// are different problems and must not render the same.
    targets: Vec<(String, usize)>,
}

/// Collapse a report into one entry per defect that reads identically.
///
/// The key is the whole rendered identity — severity, name, and message — so
/// two findings collapse only when a reader could not have told them apart on
/// the line anyway. A parameterised message that named two different header
/// values stays two entries, which is the behaviour that makes this safe to
/// switch on without reading the catalogue first.
fn group_findings(findings: &[FindingsBlock]) -> Vec<Group<'_>> {
    let mut order: Vec<Group<'_>> = Vec::new();
    let mut index: std::collections::HashMap<(lint::Severity, &str, &str), usize> =
        std::collections::HashMap::new();

    for block in findings {
        let target = match block {
            FindingsBlock::HttpTransaction(f) => format!("{} {}", f.method, f.uri),
            FindingsBlock::WebsocketSession(f) => format!("websocket session {}", f.session_id),
        };
        for v in block.violations() {
            let key = (v.severity, violation_name(v), v.message.as_str());
            let slot = *index.entry(key).or_insert_with(|| {
                order.push(Group {
                    severity: v.severity,
                    violation: v,
                    count: 0,
                    targets: Vec::new(),
                });
                order.len() - 1
            });
            let group = &mut order[slot];
            group.count += 1;
            match group.targets.iter_mut().find(|(t, _)| *t == target) {
                Some((_, n)) => *n += 1,
                None => group.targets.push((target.clone(), 1)),
            }
        }
    }

    // Loudest first, then most frequent, then by name — so the ordering is a
    // property of the findings and not of the order the capture happened to
    // hold them in.
    order.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.count.cmp(&a.count))
            .then_with(|| violation_name(a.violation).cmp(violation_name(b.violation)))
    });
    order
}

/// How many example targets a group names before it starts counting them.
const TARGETS_SHOWN: usize = 3;

/// Draw the grouped report: one entry per defect, loudest first.
fn render_groups(groups: &[Group<'_>], opts: RenderOpts) -> String {
    let mut out = String::new();
    for (i, group) in groups.iter().enumerate() {
        let v = group.violation;
        let severity = render_severity(v.severity, opts);
        let count = opts
            .styles
            .paint(opts.styles.dim(), &format!("×{}", group.count));

        if opts.detail == Detail::Brief {
            // One line, and the catalogue's own words for it. Elided rather
            // than wrapped: the whole promise of this tier is that a defect
            // takes exactly one row.
            let title = violation_title(v);
            // Measured on the plain count, never the painted one: an escape
            // sequence takes no columns on screen and would otherwise elide
            // the title by the width of its own colour.
            let room = opts.wrap.map_or(title.chars().count(), |w| {
                w.saturating_sub(10 + group.count.to_string().len())
            });
            out.push_str(&format!(
                "{severity} {count}  {}\n",
                elide_middle(&title, room)
            ));
            continue;
        }

        if i > 0 {
            out.push('\n');
        }
        let name = opts.styles.paint(opts.styles.name(), violation_name(v));
        out.push_str(&format!("{severity} {name}  {count}\n"));
        push_wrapped(&mut out, &v.message, 6, opts);
        if opts.detail != Detail::Full {
            if let Some(cite) = &v.cite {
                out.push_str(&format!("      {}\n", render_cite(cite, opts)));
            }
        }
        for (target, n) in group.targets.iter().take(TARGETS_SHOWN) {
            let room = opts
                .wrap
                .map_or(target.chars().count(), |w| w.saturating_sub(14));
            let line = match n {
                1 => elide_middle(target, room),
                n => format!("{}  ×{n}", elide_middle(target, room)),
            };
            out.push_str(&format!(
                "      {}\n",
                opts.styles.paint(opts.styles.dim(), &line)
            ));
        }
        if group.targets.len() > TARGETS_SHOWN {
            let more = plural(group.targets.len() - TARGETS_SHOWN, "other target");
            out.push_str(&format!(
                "      {}\n",
                opts.styles.paint(opts.styles.dim(), &format!("and {more}"))
            ));
        }
        if opts.detail == Detail::Full {
            render_violation_detail(v, 6, opts, &mut out);
        }
    }
    out
}

/// Render the `lint-captures` report: the text form ends with a human summary line
/// (whose violation count is derived from `findings`, so it can't disagree
/// with the blocks above it); the JSON form is a bare array of
/// [`FindingsBlock`]s so it stays machine-parseable. The summary mentions
/// websocket sessions only when the capture had any, so pure-HTTP output is
/// unchanged.
fn render_lint_report(
    findings: &[FindingsBlock],
    summary: &Summary,
    format: OutputFormat,
    opts: RenderOpts,
) -> anyhow::Result<String> {
    match format {
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(findings)?)),
        OutputFormat::Text => {
            let mut out = render_findings(findings, opts)?;
            out.push_str(&render_summary(summary, opts));
            Ok(out)
        }
    }
}

/// The body of a text report — grouped or in capture order, as asked.
fn render_findings(findings: &[FindingsBlock], opts: RenderOpts) -> anyhow::Result<String> {
    if opts.collapse() {
        return Ok(render_groups(&group_findings(findings), opts));
    }
    let mut out = String::new();
    for block in findings {
        out.push_str(&render_findings_block(block, opts)?);
    }
    Ok(out)
}

/// What a report's closing lines say.
///
/// A struct rather than a parameter list because the line grew three
/// independent clauses — what was found, what was hidden, and what failed —
/// and each of them is assembled by a different part of the report. Built in
/// one place, so a session and a replay cannot describe their tallies
/// differently.
#[derive(Debug)]
struct Summary {
    total: usize,
    /// Findings at each level, indexed by [`lint::Severity`] order.
    by_severity: [usize; 3],
    transactions: usize,
    websockets: usize,
    /// Distinct hosts the shown findings are about.
    hosts: usize,
    /// Findings the host scope kept out, and the transactions they were on.
    hidden_hosts: usize,
    hidden_host_transactions: usize,
    /// Findings `--min-severity` filtered out before the report existed.
    hidden_severity: usize,
    min_severity: lint::Severity,
    /// Findings `--about` filtered out because the other peer is answerable.
    hidden_party: usize,
    /// The peer the report was narrowed to, for the clause that names the flag.
    about: AboutScope,
    /// Findings the report is *showing* although `--about` narrowed it, because
    /// no rule has said whose they are. Not a hidden count and given a line of
    /// its own so it cannot read as one — what it measures is this tool's own
    /// incompleteness, and it disappears when the catalogue is fully read.
    unattributed: usize,
    /// The gate this report will be read by, when one was asked for.
    fail_on: Option<lint::Severity>,
}

/// An empty report of nothing, gated at the most permissive level.
///
/// Hand-written rather than derived: [`lint::Severity`] has no default and
/// should not acquire one — which of three levels a *rule* means by silence is
/// a question with no answer, while the level a *report* was gated at when
/// nobody said is plainly `info`, the same value `--min-severity` defaults to.
impl Default for Summary {
    fn default() -> Self {
        Self {
            total: 0,
            by_severity: [0; 3],
            transactions: 0,
            websockets: 0,
            hosts: 0,
            hidden_hosts: 0,
            hidden_host_transactions: 0,
            hidden_severity: 0,
            min_severity: lint::Severity::Info,
            hidden_party: 0,
            about: AboutScope::all(),
            unattributed: 0,
            fail_on: None,
        }
    }
}

impl Summary {
    /// The counts that come straight off the findings being shown. What was
    /// *not* shown — filtered by severity, scoped away by host, or about to
    /// trip a gate — is known only to the caller, and is set on the result.
    fn of(findings: &[FindingsBlock]) -> Self {
        let mut summary = Summary::default();
        let mut hosts: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for block in findings {
            if let FindingsBlock::HttpTransaction(f) = block {
                if let Some(host) = uri_host(&f.uri) {
                    hosts.insert(host);
                }
            }
            for v in block.violations() {
                summary.total += 1;
                summary.by_severity[severity_index(v.severity)] += 1;
            }
        }
        summary.hosts = hosts.len();
        summary
    }

    /// The same counts, plus the two totals every caller has to hand.
    fn counted(findings: &[FindingsBlock], transactions: usize, websockets: usize) -> Self {
        Self {
            transactions,
            websockets,
            ..Self::of(findings)
        }
    }

    /// How many findings would trip the gate, when there is one.
    fn failing(&self) -> usize {
        let Some(fail_on) = self.fail_on else {
            return 0;
        };
        [
            lint::Severity::Info,
            lint::Severity::Warn,
            lint::Severity::Error,
        ]
        .iter()
        .filter(|s| **s >= fail_on)
        .map(|s| self.by_severity[severity_index(*s)])
        .sum()
    }
}

fn severity_index(severity: lint::Severity) -> usize {
    match severity {
        lint::Severity::Info => 0,
        lint::Severity::Warn => 1,
        lint::Severity::Error => 2,
    }
}

/// The lines a text report ends with.
///
/// Its own function because a session that printed its findings as they
/// happened has nothing left to print *but* this, and a second copy of the
/// sentence is a second thing to keep in step with the first. It was two
/// copies, and the one the browsing session used had already grown a websocket
/// clause the other spelled differently.
///
/// Three lines at most, and each earns its place by being absent when it has
/// nothing to say: what was found, what was hidden and by which flag, and what
/// the gate made of it. The severity breakdown is what turns a count into a
/// verdict — `12 findings` says nothing about whether to look, and
/// `12 findings (2 errors, …)` says it in the first four words.
fn render_summary(summary: &Summary, opts: RenderOpts) -> String {
    use std::fmt::Write;
    let styles = opts.styles;
    let mut out = String::from("\n");

    // A glyph only where it will render as one: it is drawn from the same
    // decision that says a terminal is on the other end, and a redirect that
    // caught `✖` in a log has gained nothing over the word beside it.
    let glyph = |mark: &str, severity: lint::Severity| {
        if styles.is_enabled() {
            format!("{}  ", styles.paint(styles.severity(severity), mark))
        } else {
            String::new()
        }
    };

    if summary.total == 0 {
        let _ = write!(
            out,
            "{}no findings in {}",
            glyph("✔", lint::Severity::Info),
            plural(summary.transactions, "transaction")
        );
    } else {
        let worst = if summary.by_severity[2] > 0 {
            (lint::Severity::Error, "✖")
        } else if summary.by_severity[1] > 0 {
            (lint::Severity::Warn, "▲")
        } else {
            (lint::Severity::Info, "•")
        };
        let mut parts: Vec<String> = Vec::new();
        for (severity, word) in [
            (lint::Severity::Error, "error"),
            (lint::Severity::Warn, "warning"),
        ] {
            let n = summary.by_severity[severity_index(severity)];
            if n > 0 {
                parts.push(styles.paint(styles.severity(severity), &plural(n, word)));
            }
        }
        // `info` is already plural and takes no `s`, which is exactly the kind
        // of thing `violation(s)` existed to avoid deciding.
        let n = summary.by_severity[0];
        if n > 0 {
            parts.push(styles.paint(styles.severity(lint::Severity::Info), &format!("{n} info")));
        }
        let _ = write!(
            out,
            "{}{} ({}) in {}",
            glyph(worst.1, worst.0),
            styles.paint(styles.name(), &plural(summary.total, "finding")),
            parts.join(", "),
            plural(summary.transactions, "transaction")
        );
    }
    if summary.websockets > 0 {
        let _ = write!(
            out,
            " and {}",
            plural(summary.websockets, "websocket session")
        );
    }
    if summary.hosts > 1 {
        let _ = write!(out, " across {}", plural(summary.hosts, "host"));
    }
    out.push('\n');

    // One line for everything the report is not showing, whatever the reason,
    // each clause naming the flag that would show it. It was one clause that
    // grew per cause, so a report narrowed twice said so once.
    let mut hidden: Vec<String> = Vec::new();
    if summary.hidden_hosts > 0 {
        hidden.push(format!(
            "{} on other hosts in {} (--all-hosts)",
            summary.hidden_hosts,
            plural(summary.hidden_host_transactions, "transaction")
        ));
    }
    if summary.hidden_severity > 0 {
        hidden.push(format!(
            "{} below {} (--min-severity)",
            summary.hidden_severity,
            summary.min_severity.name()
        ));
    }
    if summary.hidden_party > 0 {
        // Named by the peer that *is* answerable, not by the one asked for: a
        // reader who typed `--about client` knows what they asked for and wants
        // to know what that cost them.
        let other = match summary.about.party {
            Some(lint::Party::Client) => "the server",
            _ => "the client",
        };
        hidden.push(format!(
            "{} {other} is answerable for (--about any)",
            summary.hidden_party,
        ));
    }
    if !hidden.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            styles.paint(styles.dim(), &format!("hidden: {}", hidden.join("; ")))
        );
    }

    // What the report is showing but could not measure — its own line, and not
    // a clause of `hidden:`, because these findings are on the screen. The
    // number is a fact about how much of the catalogue has been read for the
    // question, so it names no flag to reveal them: there is nothing hidden to
    // reveal. It stops rendering when every rule has been read.
    if summary.unattributed > 0 {
        let _ = writeln!(
            out,
            "{}",
            styles.paint(
                styles.dim(),
                &format!(
                    "unattributed: {} kept, because no rule says whose they are",
                    summary.unattributed
                )
            )
        );
    }

    // Why this run is about to exit non-zero, said before it does. A gate that
    // fails without naming what tripped it sends the reader back through the
    // report to work it out.
    let failing = summary.failing();
    if failing > 0 {
        if let Some(fail_on) = summary.fail_on {
            let _ = writeln!(
                out,
                "{}",
                styles.paint(
                    styles.dim(),
                    &format!("failing: --fail-on {} matched {failing}", fail_on.name())
                )
            );
        }
    }
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
    /// and `--format json > findings.json` is what the documentation has
    /// promised since it existed. The *text* report is on stderr either way,
    /// and so is every diagnostic. Which one a session is comes off its driver.
    json_to_stdout: bool,
    /// The gate this session's exit code will be read through, so the summary
    /// can say what tripped it.
    fail_on: Option<lint::Severity>,
}

/// Print one session's report, and hand back the findings a gate would read.
///
/// The whole tail of a session: gate by severity, divide by scope, print in the
/// requested format, and say what the scope left out. `run` and the browsing
/// session each had their own copy, which is why only one of them counted
/// transactions the way its own summary line claimed to.
fn report_session(
    records: &[capture::CaptureRecord],
    scope: &HostScope,
    global: &GlobalArgs,
    style: ReportStyle,
) -> anyhow::Result<Vec<FindingsBlock>> {
    let report = recorded_findings(records, global.min_severity(), global.about());
    // The report goes to stderr on a session whatever the format, except the
    // JSON document a browsing session puts on stdout — so that is the stream
    // to ask about colour, and the one clause below that changes it.
    let opts = global.render_opts(is_terminal(Stream::Stderr));

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

    let mut summary = Summary::counted(&findings, in_scope_transactions, report.websocket_count);
    summary.hidden_hosts = elsewhere;
    summary.hidden_host_transactions = report
        .transaction_count
        .saturating_sub(in_scope_transactions);
    summary.hidden_severity = report.suppressed;
    summary.min_severity = global.min_severity();
    summary.hidden_party = report.hidden_party;
    summary.about = global.about();
    summary.unattributed = report.unattributed;
    summary.fail_on = style.fail_on;

    match global.format() {
        OutputFormat::Json => {
            let document = render_lint_report(&findings, &summary, OutputFormat::Json, opts)?;
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
            // The same note for the same reason, one flag over. There is no
            // second note for what was kept unattributed: every finding in the
            // document carries `party`, so its absence *is* the marker, and a
            // machine reading the document can count them itself.
            if report.hidden_party > 0 {
                write_stderr(&format!(
                    "note: {} violation(s) the other peer is answerable for are not in this document (--about any)\n",
                    report.hidden_party
                ))?;
            }
        }
        OutputFormat::Text => {
            let mut out = String::new();
            // A live session already printed its blocks in capture order, so
            // only the tally is new — unless the report is collapsed, in which
            // case the live pass showed each defect once and *without* a count,
            // and the grouped table is the thing it was counting toward.
            if !style.live || opts.collapse() {
                out.push_str(&render_findings(&findings, opts)?);
            }
            out.push_str(&render_summary(&summary, opts));
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
    let scope = args.session.scope(&[]);
    let findings = report_session(
        &run.records,
        &scope,
        global,
        ReportStyle {
            live: false,
            json_to_stdout: false,
            fail_on: args.session.fail_on.map(Into::into),
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

/// Drive one named tool through a session of its own.
///
/// Three lines, because everything a session does is [`drive`] and everything
/// this tool needs done differently is its driver's. `browse` was these three
/// lines with `chromium` written into them.
async fn use_tool(args: UseArgs, global: &GlobalArgs) -> anyhow::Result<u8> {
    let UseArgs { command, session } = args;
    let Some((named, rest)) = command.split_first() else {
        anyhow::bail!(
            "no tool given; try `lint-http use curl https://example.com` \
             (drivers: {})",
            driver::known_names().join(", ")
        );
    };
    // `trailing_var_arg` + `allow_hyphen_values` is what lets the tool keep its
    // own flags, and it means clap cannot reject a mistyped one of ours:
    // `--fail-onn error` parses as a *tool* named `--fail-onn`. Caught here
    // rather than by the driver table, which would report it as an unknown
    // tool and send the reader looking for a driver.
    if named.starts_with('-') {
        anyhow::bail!(
            "`{named}` is not a tool. Options for lint-http go before the tool name; \
             everything after it belongs to the tool — `lint-http use [OPTIONS] <TOOL> {named} ...`"
        );
    }
    let (driver, tool) = driver::resolve(named)?;
    let invocation = driver.inspect(rest);
    drive(driver, tool, invocation, &session, global).await
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

    // An invocation that sends a body writes that body into a capture the user
    // asked to keep.
    //
    // **This does not decide what the report contains.** The live pass holds
    // every body it buffered whether or not any of them are written down, and
    // the report is the live pass — so the rules that read a body fire either
    // way. What this changes is the file: a kept capture of a `-d @order.json`
    // run records what was sent rather than only that something was. Applied
    // only when there is a file, because a session that keeps nothing would be
    // paying for octets it is about to delete.
    if invocation.sends_body && global.captures_path().is_some() {
        std::sync::Arc::make_mut(&mut cfg)
            .general
            .captures_include_body = true;
    }

    // The scope, decided before anything opens so it can be reported. The first
    // party is whatever the invocation was aimed at; with no target there is
    // none to infer.
    let scope = session_args.scope(&invocation.targets);

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
            global.about(),
            global.render_opts(is_terminal(Stream::Stderr)),
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
            fail_on: session_args.fail_on.map(Into::into),
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
    about: AboutScope,
    opts: RenderOpts,
) {
    // What a collapsed report has already said once. A session that repeats
    // one defect on every request would otherwise scroll the interesting
    // findings off the top with copies of the boring one — and under `--group`
    // or `-q` the reader has asked for exactly the opposite. Nothing is lost:
    // the end-of-session table names every defect with the count this was
    // accumulating toward, so the suppressed lines are reported as a number
    // rather than not reported.
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
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
        // The same narrowing the replayed report applies, applied here too.
        // A filter that ran only at the end would print blocks the closing
        // count did not include — the drift this function's own comment
        // records, arriving one flag later.
        let Some(mut block) = gated_block(&envelope.record, min_severity, about).block else {
            continue;
        };
        if !scope.keeps(&block) {
            continue;
        }
        if opts.collapse() {
            block.retain_violations(|v| {
                seen.insert((violation_name(v).to_string(), v.message.clone()))
            });
            if block.violations().is_empty() {
                continue;
            }
        }
        // `-q` promises one line per defect, and a live session is still that
        // tier. Everything else stays a transcript: a session someone is
        // watching wants the request the finding was on, which the brief line
        // deliberately does not carry.
        let rendered = if opts.detail == Detail::Brief {
            render_findings(std::slice::from_ref(&block), opts)
        } else {
            render_findings_block(&block, opts)
        };
        if let Ok(text) = rendered {
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
        Some(Command::Run(_) | Command::Use(_) | Command::ProxyStart)
    ) {
        init_diagnostics();
    }
    match cli.command {
        Some(Command::Run(args)) => run_wrapped(args, &global).await,
        Some(Command::Use(args)) => use_tool(args, &global).await,
        Some(Command::ProxyStart) => {
            run_app(global.config.as_deref(), global.captures.as_deref()).await?;
            Ok(0)
        }
        // Non-zero exit when findings exist, so CI fails on a dirty capture;
        // real errors (bad config / missing file) still bubble up as `Err`.
        Some(Command::LintCaptures(args)) => {
            let found = lint_app(global.config.as_deref(), &args.path(&global)?, &global).await?;
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
                write_stdout(&rules_list(
                    global.format(),
                    cfg.as_deref(),
                    global.render_opts(is_terminal(Stream::Stdout)).styles,
                )?)?;
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

    /// The options a test that is not about the options would have typed:
    /// nothing. Defaults throughout, which is text format, `info` and no
    /// colour — and no colour is the one that matters, because a test asserting
    /// on report text must not have to know about escape sequences.
    fn plain_global() -> GlobalArgs {
        GlobalArgs::default()
    }

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
            vec!["lint-http", "use", "browser"],
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &plain_global(),
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
            &GlobalArgs {
                min_severity: Some(SeverityArg::Warn),
                ..plain_global()
            },
        )
        .await?;
        assert_eq!(found, 0, "info finding must not survive a warn gate");

        // …while an `info` gate keeps it.
        let found = lint_app(
            Some(cfg.to_str().unwrap()),
            caps.to_str().unwrap(),
            &plain_global(),
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

        let reported = recorded_findings(&records, lint::Severity::Info, AboutScope::all());
        assert_eq!(reported.total(), 1, "the recorded finding must be reported");

        let replayed = lint_records(&cfg, records, lint::Severity::Info, AboutScope::all())?;
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

        let report = recorded_findings(&records, lint::Severity::Warn, AboutScope::all());
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
            .filter_map(|record| gated_block(record, lint::Severity::Warn, AboutScope::all()).block)
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

        let report = recorded_findings(&records, lint::Severity::Info, AboutScope::all());
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

    /// A block of `n` identical findings on `n` different targets, for the
    /// tests about collapsing and counting.
    fn repeated_findings(n: usize) -> Vec<FindingsBlock> {
        (0..n)
            .map(|i| {
                FindingsBlock::HttpTransaction(TransactionFindings {
                    method: "GET".to_string(),
                    uri: format!("http://example.test/{i}"),
                    status: Some(200),
                    violations: vec![sample_violation()],
                })
            })
            .collect()
    }

    /// **The shape a pipe gets has not changed.** One line per finding,
    /// severity padded to five, the name, the message, the citation in
    /// brackets with its URL — everything a script or a `grep` has ever read
    /// out of this tool. The new shapes are all behind a width, a flag, or a
    /// terminal; none of them is behind a default that would break a pipeline
    /// nobody was asked about.
    #[test]
    fn a_piped_report_keeps_one_line_per_finding() -> anyhow::Result<()> {
        let mut v = sample_violation();
        v.cite = Some(lint::SpecCitation {
            spec: "RFC 9111".to_string(),
            section: Some("5.2".to_string()),
            url: "https://example.test/rfc9111#section-5.2".to_string(),
        });
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v],
        })];
        let out = render_findings(&findings, RenderOpts::plain())?;
        assert_eq!(
            out,
            "GET http://example.test/ -> 200\n  warn  cache_control_present  missing Cache-Control  \
             [RFC 9111 §5.2 https://example.test/rfc9111#section-5.2]\n",
            "{out}"
        );
        Ok(())
    }

    /// Given a width, the name takes its own line and the message is indented
    /// under it. The alternative at a real terminal width is not a long line
    /// but the same line soft-wrapped into rows with no indent at all, which
    /// is the severity column destroying itself.
    #[test]
    fn a_width_indents_the_message_under_the_name() -> anyhow::Result<()> {
        let opts = RenderOpts {
            wrap: Some(48),
            ..RenderOpts::plain()
        };
        let out = render_findings(&sample_findings(), opts)?;
        assert!(out.contains("  warn  cache_control_present\n"), "{out}");
        assert!(out.contains("\n        missing Cache-Control\n"), "{out}");
        for line in out.lines() {
            assert!(line.chars().count() <= 48, "too wide: {line:?}");
        }
        Ok(())
    }

    /// Grouping collapses what reads identically and **counts it**, which is
    /// the whole difference between this and the deduplication that was
    /// abandoned: nothing is dropped, so six findings on six targets stay six
    /// in the total and say so on the entry.
    #[test]
    fn grouping_counts_rather_than_drops() -> anyhow::Result<()> {
        let findings = repeated_findings(6);
        let opts = RenderOpts {
            group: true,
            ..RenderOpts::plain()
        };
        let out = render_findings(&findings, opts)?;
        assert_eq!(out.matches("cache_control_present").count(), 1, "{out}");
        assert!(out.contains("×6"), "{out}");
        // Three targets shown, and the rest counted rather than dropped.
        assert!(out.contains("GET http://example.test/0"), "{out}");
        assert!(out.contains("and 3 other targets"), "{out}");
        // And the tally still knows there were six.
        let summary = Summary::counted(&findings, 6, 0);
        assert!(
            render_summary(&summary, opts).contains("6 findings"),
            "{out}"
        );
        Ok(())
    }

    /// Two findings that merely *read* alike are two entries, not one. The key
    /// is the whole rendered identity, so a parameterised message naming two
    /// different values never collapses — which is what makes `--group` safe
    /// to switch on without reading the catalogue first.
    #[test]
    fn grouping_keys_on_the_whole_message() -> anyhow::Result<()> {
        let mut other = sample_violation();
        other.message = "missing Expires".to_string();
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![sample_violation(), other],
        })];
        let groups = group_findings(&findings);
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g.count == 1));
        Ok(())
    }

    /// The loudest defect leads, whatever order the capture held them in.
    #[test]
    fn grouping_puts_the_loudest_first() {
        let mut loud = sample_violation();
        loud.severity = lint::Severity::Error;
        loud.message = "malformed".to_string();
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![sample_violation(), loud],
        })];
        let groups = group_findings(&findings);
        assert_eq!(groups[0].severity, lint::Severity::Error);
    }

    /// `-q` prints the catalogue's own one-line title for the defect — the
    /// field 537 entries carry and the report never showed, written to be read
    /// out of context, which is exactly this tier's job.
    #[test]
    fn the_brief_tier_prints_the_catalogue_title() -> anyhow::Result<()> {
        // A real catalogue id, so the lookup is the one a real finding does.
        let id = "cache_control_missing";
        let def = violations::by_id(id).expect("a catalogue entry for a real id");
        let mut v = sample_violation();
        v.violation = id.to_string();
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v],
        })];
        let out = render_findings(
            &findings,
            RenderOpts {
                detail: Detail::Brief,
                ..RenderOpts::plain()
            },
        )?;
        assert_eq!(out, format!("warn  ×1  {}\n", def.title), "{out}");
        // And the message it replaced is not on the line.
        assert!(!out.contains("missing Cache-Control"), "{out}");
        Ok(())
    }

    /// A finding whose defect the catalogue does not know still says
    /// something: the message, not the bare id, which is already on the line
    /// in the ungrouped tiers and would be the only content of this one.
    #[test]
    fn the_brief_tier_falls_back_to_the_message() {
        assert_eq!(
            violation_title(&sample_violation()),
            "missing Cache-Control"
        );
    }

    /// **The citation compacts only because the label is clickable.** Under
    /// colour it is the label alone with the URL behind an OSC 8 hyperlink;
    /// without colour there is no hyperlink, so the URL is printed exactly as
    /// it always was rather than being silently lost from a report in a file.
    #[test]
    fn a_citation_keeps_its_url_wherever_it_cannot_be_a_link() {
        let cite = lint::SpecCitation {
            spec: "RFC 9110".to_string(),
            section: Some("12.5.3".to_string()),
            url: "https://example.test/rfc9110#section-12.5.3".to_string(),
        };
        let plain = render_cite(&cite, RenderOpts::plain());
        assert_eq!(
            plain,
            "[RFC 9110 §12.5.3 https://example.test/rfc9110#section-12.5.3]"
        );

        let coloured = render_cite(
            &cite,
            RenderOpts {
                styles: style::Styles::new(true),
                ..RenderOpts::plain()
            },
        );
        assert!(coloured.contains("\x1b]8;;https://example.test/rfc9110#section-12.5.3"));
        assert!(coloured.contains("RFC 9110 §12.5.3"));
        // The URL is a hyperlink target, not text: it appears once, in the
        // escape, and never beside the label it replaced.
        assert_eq!(coloured.matches("https://").count(), 1, "{coloured:?}");
    }

    /// `-v` says the four things the line has no room for, and names the
    /// stanza that switches the defect off.
    #[test]
    fn the_full_tier_names_the_rule_the_docs_and_the_off_switch() -> anyhow::Result<()> {
        let mut v = sample_violation();
        v.violation = "cache_control_missing".to_string();
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v],
        })];
        let out = render_findings(
            &findings,
            RenderOpts {
                detail: Detail::Full,
                ..RenderOpts::plain()
            },
        )?;
        assert!(out.contains("rule  cache_control_present"), "{out}");
        assert!(
            out.contains("docs  docs/violations/cache_control_missing.md"),
            "{out}"
        );
        assert!(
            out.contains("hush  [violations.cache_control_missing]"),
            "{out}"
        );
        assert!(out.contains("enabled = false"), "{out}");
        Ok(())
    }

    /// **A defect that names two governing statements still has a `spec`
    /// block.** A finding carries a citation only when its defect has exactly
    /// one, so reading the references off the finding left the 19 entries that
    /// name two with nothing under `spec` — and their catalogue notes printed
    /// anyway, indented under no heading at all.
    #[test]
    fn the_full_tier_reads_its_references_from_the_catalogue() -> anyhow::Result<()> {
        // A real defect with two governing statements and therefore no
        // citation on the finding, which is the shape that used to orphan.
        let two = violations::VIOLATIONS
            .iter()
            .find(|d| d.spec.len() > 1)
            .expect("the catalogue holds a defect with two governing statements");
        let mut v = sample_violation();
        v.violation = two.id.to_string();
        v.cite = None;
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v],
        })];
        let out = render_findings(
            &findings,
            RenderOpts {
                detail: Detail::Full,
                ..RenderOpts::plain()
            },
        )?;
        assert_eq!(out.matches("spec  ").count(), two.spec.len(), "{out}");
        for spec in two.spec {
            assert!(out.contains(spec.url), "{out}");
            // Every note sits under a heading, never on its own.
            if !spec.note.is_empty() {
                assert!(out.contains(spec.note), "{out}");
            }
        }
        Ok(())
    }

    /// A clean report says so in words, and says how much it looked at — a
    /// count of zero over no denominator is the shape a broken interception
    /// and a tidy run both used to print.
    #[test]
    fn a_clean_report_says_what_it_looked_at() {
        let summary = Summary::counted(&[], 12, 0);
        assert_eq!(
            render_summary(&summary, RenderOpts::plain()),
            "\nno findings in 12 transactions\n"
        );
    }

    /// Everything the report is not showing goes on one line, each clause
    /// naming the flag that would show it. It was one clause that grew per
    /// cause, so a report narrowed twice said so once.
    #[test]
    fn every_suppression_is_named_on_one_line() {
        let findings = sample_findings();
        let summary = Summary {
            hidden_hosts: 26,
            hidden_host_transactions: 7,
            hidden_severity: 4,
            min_severity: lint::Severity::Warn,
            ..Summary::counted(&findings, 6, 0)
        };
        let out = render_summary(&summary, RenderOpts::plain());
        assert!(
            out.contains(
                "hidden: 26 on other hosts in 7 transactions (--all-hosts); \
                 4 below warn (--min-severity)\n"
            ),
            "{out}"
        );
    }

    /// A finding attributed to `party`, for the tests about `--about`.
    fn violation_by(party: Option<lint::Party>) -> lint::Violation {
        lint::Violation {
            party,
            ..sample_violation()
        }
    }

    /// One transaction carrying findings of both peers, one decided as
    /// neither's, and one nobody has read — the shape every `--about` test
    /// needs, because a transaction routinely carries all of them at once.
    fn mixed_violations() -> Vec<lint::Violation> {
        vec![
            violation_by(Some(lint::Party::Client)),
            violation_by(Some(lint::Party::Server)),
            violation_by(Some(lint::Party::Neither)),
            violation_by(None),
        ]
    }

    fn mixed_record() -> capture::CaptureRecord {
        let mut tx = lint_http_core::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.violations = mixed_violations();
        capture::CaptureRecord::HttpTransaction(Box::new(tx))
    }

    /// **`--about any` is the identity.** The whole migration rests on it: a
    /// report nobody narrowed must be byte-for-byte what it was before the flag
    /// existed, or every existing reader's output moved for a feature they did
    /// not ask for.
    #[test]
    fn an_unnarrowed_report_keeps_every_finding() {
        let gated = gated_block(&mixed_record(), lint::Severity::Info, AboutScope::all());
        assert_eq!(gated.block.expect("a block").violations().len(), 4);
        assert_eq!(gated.hidden_party, 0);
        assert_eq!(
            gated.unattributed, 0,
            "a report nobody narrowed has no incompleteness to report",
        );
    }

    /// Narrowing to one peer keeps that peer's findings, the ones decided as
    /// neither's, and the ones nobody has read — and drops only the other
    /// peer's.
    #[test]
    fn narrowing_to_a_peer_keeps_what_it_cannot_measure() {
        for (party, hidden) in [(lint::Party::Client, 1), (lint::Party::Server, 1)] {
            let about = AboutScope { party: Some(party) };
            let gated = gated_block(&mixed_record(), lint::Severity::Info, about);
            let kept = gated.block.expect("a block");
            assert_eq!(
                kept.violations().len(),
                3,
                "the named peer's, neither's, and the unread one",
            );
            assert_eq!(gated.hidden_party, hidden);
            assert_eq!(gated.unattributed, 1);
            // The one dropped is the other peer's, and nothing else.
            assert!(kept
                .violations()
                .iter()
                .all(|v| v.party != Some(other_party(party))));
        }
    }

    fn other_party(party: lint::Party) -> lint::Party {
        match party {
            lint::Party::Client => lint::Party::Server,
            _ => lint::Party::Client,
        }
    }

    /// **A finding below the severity gate is counted once.** It was never in
    /// the report for `--about` to have an opinion about, so counting it in
    /// both clauses would tell a reader the same finding was hidden twice.
    #[test]
    fn a_finding_below_the_gate_is_not_also_counted_as_the_other_peers() {
        let mut tx = lint_http_core::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.violations = vec![lint::Violation {
            party: Some(lint::Party::Server),
            severity: lint::Severity::Info,
            ..sample_violation()
        }];
        let gated = gated_block(
            &capture::CaptureRecord::HttpTransaction(Box::new(tx)),
            lint::Severity::Warn,
            AboutScope {
                party: Some(lint::Party::Client),
            },
        );
        assert!(gated.block.is_none());
        assert_eq!(gated.suppressed, 1);
        assert_eq!(gated.hidden_party, 0, "counted by severity, and only once");
    }

    /// The two new clauses join the line that was already there, and the
    /// unattributed count gets a line of its own — it is not hidden, so it may
    /// not read as if it were.
    #[test]
    fn a_narrowed_report_says_what_it_dropped_and_what_it_could_not_measure() {
        let findings = sample_findings();
        let summary = Summary {
            hidden_hosts: 26,
            hidden_host_transactions: 7,
            hidden_severity: 4,
            min_severity: lint::Severity::Warn,
            hidden_party: 12,
            about: AboutScope {
                party: Some(lint::Party::Client),
            },
            unattributed: 31,
            ..Summary::counted(&findings, 6, 0)
        };
        let out = render_summary(&summary, RenderOpts::plain());
        assert!(
            out.contains(
                "hidden: 26 on other hosts in 7 transactions (--all-hosts); \
                 4 below warn (--min-severity); \
                 12 the server is answerable for (--about any)\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("unattributed: 31 kept, because no rule says whose they are\n"),
            "{out}"
        );
    }

    /// A report nobody narrowed says nothing about either — the clauses are
    /// added by a filter, not by the feature existing.
    #[test]
    fn an_unnarrowed_report_mentions_neither_clause() {
        let findings = sample_findings();
        let summary = Summary::counted(&findings, 1, 0);
        let out = render_summary(&summary, RenderOpts::plain());
        assert!(!out.contains("--about"), "{out}");
        assert!(!out.contains("unattributed"), "{out}");
    }

    /// A gate that fails says what tripped it, before the exit code does.
    #[test]
    fn a_failing_gate_says_what_matched() {
        let mut v = sample_violation();
        v.severity = lint::Severity::Error;
        let findings = vec![FindingsBlock::HttpTransaction(TransactionFindings {
            method: "GET".to_string(),
            uri: "http://example.test/".to_string(),
            status: Some(200),
            violations: vec![v, sample_violation()],
        })];
        let summary = Summary {
            fail_on: Some(lint::Severity::Warn),
            ..Summary::counted(&findings, 1, 0)
        };
        let out = render_summary(&summary, RenderOpts::plain());
        assert!(out.contains("failing: --fail-on warn matched 2"), "{out}");

        // And a gate nobody asked for says nothing at all.
        let quiet = Summary::counted(&findings, 1, 0);
        assert!(
            !render_summary(&quiet, RenderOpts::plain()).contains("failing:"),
            "a report with no gate should not mention one"
        );
    }

    /// The summary counts hosts only when there is more than one to count —
    /// `across 1 host` is a clause that never tells anybody anything.
    #[test]
    fn hosts_are_counted_only_when_there_are_several() {
        let findings = vec![
            FindingsBlock::HttpTransaction(TransactionFindings {
                method: "GET".to_string(),
                uri: "http://a.test/".to_string(),
                status: Some(200),
                violations: vec![sample_violation()],
            }),
            FindingsBlock::HttpTransaction(TransactionFindings {
                method: "GET".to_string(),
                uri: "http://b.test/".to_string(),
                status: Some(200),
                violations: vec![sample_violation()],
            }),
        ];
        let out = render_summary(&Summary::counted(&findings, 2, 0), RenderOpts::plain());
        assert!(out.contains("across 2 hosts"), "{out}");
        assert!(!render_summary(
            &Summary::counted(&sample_findings(), 1, 0),
            RenderOpts::plain()
        )
        .contains("across"),);
    }

    /// A word is never broken, whatever it costs: half a URL cannot be
    /// clicked, copied or recognised, and a long line can be all three.
    #[test]
    fn wrapping_never_breaks_a_word() {
        let long = "https://example.test/a/very/long/path/that/exceeds/the/column/on/its/own";
        let lines = wrap_text(&format!("see {long} now"), 0, 30);
        assert!(lines.iter().any(|l| l == long), "{lines:?}");
        assert_eq!(
            lines.concat().replace(' ', "").len(),
            format!("see{long}now").len()
        );
    }

    /// A target too wide for its column loses its middle, not its end: the
    /// head names the host and the tail names the resource, and the part a
    /// reader skims is the part between them.
    #[test]
    fn elision_keeps_both_ends() {
        let out = elide_middle("https://example.test/orders/1234/items", 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.starts_with("https://ex"), "{out}");
        assert!(out.ends_with("items"), "{out}");
        // Short enough to fit is left exactly alone.
        assert_eq!(elide_middle("short", 20), "short");
    }

    /// `--width 0` means "do not wrap", not "wrap at nothing".
    #[test]
    fn width_zero_is_not_a_column() {
        let global = GlobalArgs {
            width: Some(0),
            ..GlobalArgs::default()
        };
        assert_eq!(global.wrap(true), None);
        // And a stream that is not a terminal is never wrapped, whatever
        // `COLUMNS` said, because the only reader there is another program.
        assert_eq!(GlobalArgs::default().wrap(false), None);
    }

    /// `-q` and `-v` are the two ends of one dial and clap refuses both.
    #[test]
    fn the_two_verbosity_flags_are_exclusive() {
        assert!(
            Cli::try_parse_from(["lint-http", "-q", "-v", "lint-captures", "x.jsonl"]).is_err()
        );
        for (argv, detail) in [
            (
                vec!["lint-http", "lint-captures", "x.jsonl"],
                Detail::Normal,
            ),
            (
                vec!["lint-http", "-q", "lint-captures", "x.jsonl"],
                Detail::Brief,
            ),
            (
                vec!["lint-http", "lint-captures", "-v", "x.jsonl"],
                Detail::Full,
            ),
        ] {
            assert_eq!(Cli::parse_from(&argv).global.detail(), detail, "{argv:?}");
        }
    }

    #[test]
    fn render_lint_report_json_mirrors_the_text_block() -> anyhow::Result<()> {
        let out = render_lint_report(
            &sample_findings(),
            &Summary::counted(&sample_findings(), 3, 0),
            OutputFormat::Json,
            RenderOpts::plain(),
        )?;
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
        let out = render_lint_report(
            &findings,
            &Summary::counted(&findings, 1, 0),
            OutputFormat::Json,
            RenderOpts::plain(),
        )?;
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
        let out = render_lint_report(
            &findings,
            &Summary::counted(&findings, 1, 0),
            OutputFormat::Text,
            RenderOpts::plain(),
        )?;
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
        let out = render_lint_report(
            &findings,
            &Summary::counted(&findings, 1, 0),
            OutputFormat::Text,
            RenderOpts::plain(),
        )?;
        // The defect leads, because it is the unit of report — the name
        // `[violations.*]` tunes and the one a capture is grepped for. The
        // rule that found it is a `-v` away, and the two used to be printed
        // together on every line with their shared stem spelled twice.
        assert!(
            out.contains("warn  cache_control_missing  missing"),
            "{out}"
        );
        // A finding that names no defect still prints under its rule id: that
        // is the only name it has.
        assert!(
            out.contains("warn  cache_control_present  missing"),
            "{out}"
        );

        let json = render_lint_report(
            &findings,
            &Summary::counted(&findings, 1, 0),
            OutputFormat::Json,
            RenderOpts::plain(),
        )?;
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
        let out = render_lint_report(
            &sample_findings(),
            &Summary::counted(&sample_findings(), 3, 0),
            OutputFormat::Text,
            RenderOpts::plain(),
        )?;
        assert!(out.contains("GET http://example.test/ -> 200"));
        assert!(out.contains("warn  cache_control_present"));
        // No websocket sessions in the capture → summary is the pure-HTTP form.
        // Real plurals, and the severity breakdown that turns a count into a
        // verdict: `1 finding` says nothing about whether to look.
        assert!(
            out.ends_with("1 finding (1 warning) in 3 transactions\n"),
            "{out}"
        );
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

        let text = render_lint_report(
            &findings,
            &Summary::counted(&findings, 0, 2),
            OutputFormat::Text,
            RenderOpts::plain(),
        )?;
        assert!(text.contains(&format!(
            "websocket session {session_id} (upgrade {transaction_id}) -> close 1000"
        )));
        assert!(
            text.ends_with("1 finding (1 warning) in 0 transactions and 2 websocket sessions\n"),
            "{text}"
        );

        let json = render_lint_report(
            &findings,
            &Summary::counted(&findings, 0, 2),
            OutputFormat::Json,
            RenderOpts::plain(),
        )?;
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

        let driven = Cli::parse_from([
            "lint-http",
            "use",
            "--fail-on",
            "warn",
            "browser",
            "https://example.com/",
        ]);
        match driven.command {
            Some(Command::Use(args)) => {
                assert!(matches!(args.session.fail_on, Some(SeverityArg::Warn)));
            }
            other => panic!("expected Use, got {other:?}"),
        }
    }

    /// The scope a session reports, in the order the three inputs win.
    #[test]
    fn a_session_scopes_to_its_target_unless_told_otherwise() {
        let target = &["https://example.com/app".to_string()][..];

        // Nothing said, and a target to infer from: that target's host.
        let inferred = SessionArgs::default().scope(target);
        assert!(inferred.includes("https://api.example.com/v1"));
        assert!(!inferred.includes("https://cdn.other.net/x"));

        // Nothing said and no target — `run --`, which cannot know one.
        assert!(SessionArgs::default().scope(&[]).is_all());

        // Every target, not the first: one invocation may name two hosts, and
        // scoping to one of them would drop the other without saying so.
        let both = SessionArgs::default().scope(&[
            "https://example.com/".to_string(),
            "https://www.iana.org/".to_string(),
        ]);
        assert!(both.includes("https://example.com/"));
        assert!(both.includes("https://www.iana.org/"));
        assert!(!both.includes("https://cdn.other.net/x"));

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

    /// The tool is named, and everything after it is the tool's.
    #[test]
    fn cli_use_takes_a_tool_and_leaves_the_rest_to_it() {
        match Cli::parse_from(["lint-http", "use", "browser", "https://example.com/app"]).command {
            Some(Command::Use(args)) => {
                assert!(args.session.only_host.is_empty());
                assert!(!args.session.all_hosts);
                assert_eq!(args.command, ["browser", "https://example.com/app"]);
            }
            other => panic!("expected Use, got {other:?}"),
        }
    }

    /// **The passthrough promise, at the CLI.** An option that would be a
    /// lint-http option if it came earlier is the tool's once the tool is
    /// named, and reaches it unchanged — which is what makes `use` safe to
    /// type in front of a command nobody has read the flags of.
    #[test]
    fn an_option_after_the_tool_belongs_to_the_tool() {
        match Cli::parse_from([
            "lint-http",
            "use",
            "curl",
            "--fail-on",
            "error",
            "-sS",
            "https://example.com/",
        ])
        .command
        {
            Some(Command::Use(args)) => {
                assert!(
                    args.session.fail_on.is_none(),
                    "--fail-on after the tool is curl's"
                );
                assert_eq!(
                    args.command,
                    ["curl", "--fail-on", "error", "-sS", "https://example.com/"]
                );
            }
            other => panic!("expected Use, got {other:?}"),
        }
    }

    #[test]
    fn cli_use_rejects_scoping_two_ways_at_once() {
        assert!(Cli::try_parse_from([
            "lint-http",
            "use",
            "--all-hosts",
            "--only-host",
            "example.com",
            "browser",
        ])
        .is_err());
    }

    /// A scoped report divides like with like, and says what it left out.
    ///
    /// **The number this pins is the transaction count.** A scoped violation
    /// count over an unscoped transaction count reads as "1 violation(s) in 2
    /// transaction(s)" when one of those two was never in the report's scope at
    /// all — the reader is then told the session was quieter than it was.
    #[test]
    fn a_scoped_report_counts_only_what_it_is_about() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let mut mine = make_test_transaction_with_response(200, &[]);
        mine.request.uri = "https://example.com/a".to_string();
        mine.violations = vec![sample_violation()];
        let mut theirs = make_test_transaction_with_response(200, &[]);
        theirs.request.uri = "https://cdn.other.net/b".to_string();
        theirs.violations = vec![sample_violation(), sample_violation()];

        let records: Vec<capture::CaptureRecord> = [mine, theirs]
            .into_iter()
            .map(|tx| capture::CaptureRecord::HttpTransaction(Box::new(tx)))
            .collect();

        let global = Cli::parse_from(["lint-http", "run", "--", "true"]).global;
        let scope = HostScope::new(["example.com".to_string()]);
        let findings = report_session(
            &records,
            &scope,
            &global,
            ReportStyle {
                live: false,
                json_to_stdout: false,
                fail_on: None,
            },
        )?;
        assert_eq!(findings.len(), 1, "one block, and it is the first party's");
        assert_eq!(findings[0].violations().len(), 1);

        // Unscoped, the same records are all one report.
        let every = report_session(
            &records,
            &HostScope::all(),
            &global,
            ReportStyle {
                live: false,
                json_to_stdout: false,
                fail_on: None,
            },
        )?;
        assert_eq!(every.len(), 2);
        assert_eq!(every.iter().map(|f| f.violations().len()).sum::<usize>(), 3);
        Ok(())
    }

    /// A live session has printed its blocks already, and a JSON one is a
    /// document — neither changes which findings the gate then reads.
    #[test]
    fn how_a_report_is_delivered_does_not_change_what_it_contains() -> anyhow::Result<()> {
        use lint_http_core::test_helpers::make_test_transaction_with_response;

        let mut tx = make_test_transaction_with_response(200, &[]);
        tx.violations = vec![sample_violation()];
        let records = vec![capture::CaptureRecord::HttpTransaction(Box::new(tx))];

        let text = Cli::parse_from(["lint-http", "run", "--", "true"]).global;
        let json = Cli::parse_from(["lint-http", "--format", "json", "run", "--", "true"]).global;
        let styles = [
            (
                &text,
                ReportStyle {
                    live: true,
                    json_to_stdout: false,
                    fail_on: None,
                },
            ),
            (
                &text,
                ReportStyle {
                    live: false,
                    json_to_stdout: false,
                    fail_on: None,
                },
            ),
            (
                &json,
                ReportStyle {
                    live: false,
                    json_to_stdout: true,
                    fail_on: None,
                },
            ),
            (
                &json,
                ReportStyle {
                    live: false,
                    json_to_stdout: false,
                    fail_on: None,
                },
            ),
        ];
        for (global, style) in styles {
            let findings = report_session(&records, &HostScope::all(), global, style)?;
            assert_eq!(findings.len(), 1, "{style:?}");
        }
        Ok(())
    }

    /// `use` needs a tool, and a mistyped option is not one.
    ///
    /// `trailing_var_arg` means clap cannot reject one of ours: `--fail-onn`
    /// parses as a *tool* by that name. Caught before the driver table, which
    /// would otherwise report it as an unknown tool and send the reader looking
    /// for a driver that was never the problem.
    #[tokio::test]
    async fn dispatch_use_needs_a_tool_and_says_which_it_knows() {
        let err = dispatch(Cli::parse_from(["lint-http", "use"]))
            .await
            .expect_err("a tool is required");
        assert!(err.to_string().contains("curl"), "{err}");

        let err = dispatch(Cli::parse_from([
            "lint-http",
            "use",
            "--fail-onn",
            "error",
            "curl",
        ]))
        .await
        .expect_err("a flag is not a tool");
        assert!(err.to_string().contains("is not a tool"), "{err}");
    }

    /// A whole driven session, with a tool that is a shell script.
    ///
    /// The point is the path from a name to an exit code: resolve the driver,
    /// stand a proxy up, let the driver write the session onto the command
    /// line, run it, drain the captures, report, and exit with the child's
    /// code. The script is named `curl` so the driver table picks the curl
    /// driver off its stem — which also proves the stem is what selects, not
    /// the executable's contents.
    #[cfg(unix)]
    #[tokio::test]
    async fn dispatch_use_drives_a_tool_and_keeps_its_exit_code() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lint-http-use-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).await?;
        let script = dir.join("curl");
        // It ignores every option the driver hands it, which is the one thing a
        // stand-in for curl has to do.
        fs::write(&script, "#!/bin/sh\nexit 7\n").await?;
        fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).await?;

        let cli = Cli::parse_from(["lint-http", "use", &script.to_string_lossy()]);
        assert_eq!(
            dispatch(cli).await?,
            7,
            "the tool's exit code is the session's"
        );

        fs::remove_dir_all(&dir).await?;
        Ok(())
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
        // Every subcommand's long help as well as the binary's: a note leaks
        // into whichever one carries the argument it was written next to, and
        // the top-level rendering does not show a subcommand's arguments.
        let mut command = Cli::command();
        let help = std::iter::once(command.render_long_help().to_string())
            .chain(
                command
                    .get_subcommands_mut()
                    .map(|sub| sub.render_long_help().to_string()),
            )
            .collect::<Vec<_>>()
            .join("\n");
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
            // And `use`'s, on why its tool and arguments are one list.
            "starts at the *first* value",
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
        let out = rules_list(OutputFormat::Text, None, style::Styles::default())?;
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
        let out = rules_list(OutputFormat::Json, None, style::Styles::default())?;
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
        let out = rules_list(OutputFormat::Json, None, style::Styles::default())?;
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

        let text = rules_list(OutputFormat::Text, Some(&cfg), style::Styles::default())?;
        let line = text
            .lines()
            .find(|l| l.starts_with("cache_control_present"))
            .expect("rule line present");
        assert!(line.contains(" enabled "));
        assert!(text.contains(" disabled "));

        let json = rules_list(OutputFormat::Json, Some(&cfg), style::Styles::default())?;
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
