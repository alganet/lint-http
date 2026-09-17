<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Configuration

`lint-http` is configured using a TOML file, and every command that accepts one
may also be given none: `--config` is optional throughout, and omitting it runs
the configuration compiled into the binary. That built-in is `config_example.toml`
itself — the whole rule catalogue enabled, with `[general]` and `[tls]` set to
values that work unattended — so nothing has to be written before the tool does
anything. `lint-http config export` prints it for editing.

A named config **replaces** the built-in rather than layering over it. Rules are
off unless a config names them, so a file listing three rules enables three
rules; export and edit if you want the catalogue minus a few.

## Global options

Four options mean the same thing wherever they appear, and may be given before
or after the subcommand — `lint-http --config c.toml run -- curl` and
`lint-http run --config c.toml -- curl` are the same command line.

| Option | Meaning |
|---|---|
| `--config <PATH>` | Config TOML. Omitted, the built-in configuration is used. |
| `--format <text\|json>` | Report format. Default `text`. |
| `--min-severity <info\|warn\|error>` | Only report findings at or above this. Default `info`. |
| `--captures <PATH>` | The JSONL capture file this command reads or writes. |

`--captures` is one file under one name across the surface: `run`, `browse` and
`proxy-start` **write** it, `lint-captures` **reads** it. So what a run keeps is
what a later lint replays:

```bash
lint-http run --captures run.jsonl -- pytest
lint-http lint-captures --captures run.jsonl      # same file, same flag
lint-http lint-captures run.jsonl                 # or as the positional
```

For `run` and `browse`, `--captures` is also what makes the capture survive at
all — without it they discard theirs. For `proxy-start` it overrides the
`general.captures` path in the config.

## Command-Line Options

`lint-http` uses subcommands:

- `run [OPTIONS] -- <COMMAND>...`: Run a command with its HTTP traffic proxied
  and linted (see below). The most common entry point; nothing needs configuring.
- `browse [OPTIONS] [URL]`: Open a Chromium-family browser through a proxy of
  its own and report as it loads (see below).
- `proxy-start [--config <PATH>]`: Start the intercepting proxy and leave it
  listening.
- `lint-captures [--config <PATH>] [--format text|json]
  [--min-severity info|warn|error] <CAPTURES>`: Lint a recorded capture file
  offline (see below).
- `config export`: Print the built-in configuration to stdout.
- `rules list [--format text|json] [--config <PATH>]`: List every rule and its
  metadata (id, scope, title, and — in JSON — description, spec references, and
  documentation examples). No config or proxy needed; it prints the static
  catalogue. With `--config`, each rule is additionally annotated with whether
  that config enables it (an `enabled`/`disabled` text column, an `enabled`
  JSON field).
- `-h, --help`: Print help (works on the binary and on each subcommand)
- `-V, --version`: Print version

Example:

```bash
lint-http proxy-start --config config.toml
```

## Session options

`run` and `browse` both stand a proxy up for a child process, and they take the
same four options for it. They are declared once, so a flag means the same thing
whichever command it is typed after.

| Option | Meaning |
|---|---|
| `--fail-on <info\|warn\|error>` | Exit non-zero when a finding **in the report** reaches this severity. Findings `--min-severity` filtered out cannot trip it. Without it, the exit code is the child's. |
| `--only-host <HOST>` | Report findings for this host and anything under it. Repeatable. |
| `--all-hosts` | Report every host, including third parties the target pulls in. |
| `--show-child-stderr` | Let the child's stderr through. Off by default, so the report has stderr to itself. |

Without either scoping flag, the report covers the host of whatever the session
was pointed at — the URL `browse` opened. `run --` is tool-blind and knows no
target, so it reports every origin the child reached.

## Wrapping a command

`lint-http run [OPTIONS] -- <COMMAND>...` binds a proxy on an ephemeral port,
generates a CA into a temporary directory, puts both into the child's
environment, runs it, and reports what crossed.

```bash
lint-http run -- curl https://example.com
lint-http run --min-severity warn -- npm install
lint-http run --fail-on error --captures run.jsonl -- pytest
```

- **The report goes to stderr, and the wrapped command's stderr is discarded.**
  Two streams were competing for it and only one of them is what you ran the
  command to read. Stdout is untouched — it is the wrapped command's real
  output — so the two separate with a plain redirect:

  ```bash
  lint-http run -- curl -sS https://example.com > body.html 2> report.txt
  ```

  `--show-child-stderr` hands the child's stderr back when the wrapped command
  is itself what is being debugged. Note this does hide progress output from
  tools that write it to stderr (`npm`, `pytest`); that flag is the way back.
- `--min-severity` decides what the report contains; `--fail-on` decides what the
  exit code means. Without `--fail-on`, the exit code is the wrapped command's,
  untouched. With it, a clean child that produced findings at or above that
  severity exits 1 — but a child that failed keeps its own code.
- The report goes to **stderr**. Stdout belongs to the wrapped command, so
  `lint-http run -- curl -sS https://example.com > body.json` writes only the body.
- `--captures <PATH>` keeps the capture file. Without it, the run leaves nothing
  behind: the temporary directory, and the per-run CA inside it, are removed when
  it ends.
- `--print-env` lists the variables a wrapped command receives, and which client
  reads each one, without running anything.
- `--only-host` scopes the report the same way it does for `browse`, which
  matters as soon as the wrapped command reaches more than one origin.
- **The report is what the proxy found, not a second pass over the capture.**
  The rules ran on each transaction as it crossed, with its body in hand, and
  the finding was written onto the record; the report reads it back. That is why
  the rules that read a body appear here and not in `lint-captures`, which
  replays from a file no body survives into.

The variables and the clients that read them are a table in
`lint-http-proxy/src/client_env.rs`, where each row quotes the documentation that
defines it — so `just quotes` fails when a client's documentation drifts. The
same module header lists the clients no environment variable can reach.

## Browsing a site

`lint-http browse [URL]` launches a browser with a throwaway profile, pointed at
an ephemeral proxy, trusting the session CA by public-key pin.

```bash
lint-http browse https://example.com
lint-http browse --only-host example.com --only-host api.example.com https://example.com
lint-http browse --all-hosts --format json https://example.com > findings.json
```

- **Findings are scoped.** With a URL and no other instruction the report covers
  that URL's host and anything under it; everything else is counted on the last
  line. This is not tidiness — with the whole catalogue enabled, an unscoped
  session on a real page buries its own findings under a third-party CDN's.
- `--fail-on` gates a browsing session exactly as it gates a wrapped command,
  which is what makes one usable in a script.
- **Findings print as they happen**, because a browsing session lasts as long as
  someone keeps it open. `--format json` opts back into one report at the end.
- **The browser's stderr is discarded**, as it is for `run`. A browser writes a
  great deal of it and none of it is about the site being linted;
  `--show-child-stderr` brings it back.
- **Nothing is installed.** The CA is trusted through
  `--ignore-certificate-errors-spki-list`, which pins one public key for one
  launch. It is not `--ignore-certificate-errors`: verification stays on, so the
  session can still be trusted to judge TLS.
- **Loopback is not bypassed.** Chromium skips the proxy for `localhost` by
  default, which would make `browse http://localhost:3000` load perfectly and
  report nothing.
- Chromium-family only. Firefox verifies through its own NSS database and has no
  per-launch pin, so trusting a CA there means `certutil` against a profile or an
  enterprise policy file next to the installation — a separate piece of work
  rather than a flag.

## Linting recorded captures

`lint-http lint-captures [--config <PATH>] <CAPTURES>` replays a JSONL capture file (the
`captures` file the proxy writes) through the rule engine without running a
proxy — the CI story: lint recorded HTTP fixtures offline.

```bash
lint-http lint-captures --config config.toml captures.jsonl
```

It replays the records in file order. Each transaction is linted against the
history of prior transactions, exactly as it would be live, so stateful rules
work. WebSocket session records are replayed per-message through the protocol
rules (the frame events the live relay emits are rebuilt from the captured
message metadata); the session's live-recorded `violations` field is ignored —
replay re-lints under the current config. **A replay is not a live pass and does
not claim to be**: request and response bodies are not written to a capture, so
the rules that read one cannot fire here, and where the two disagree the live
pass is the canonical one. `run` and `browse` report their own live findings for
exactly this reason. It prints one block per offending
record and a summary line. The exit code is the signal for CI:

- **0** — no violations found.
- **1** — violations found, or an error occurred (e.g. missing capture file,
  malformed config).

Two flags shape the report:

- `--format text|json` (default `text`): `json` emits a machine-parseable array
  with one object per offending record, tagged by `kind`. Transactions
  (`"kind": "http_transaction"`) carry `method`, `uri`, `status` (`null` when
  the transaction got no response); WebSocket sessions
  (`"kind": "websocket_session"`) carry `session_id`, `transaction_id`,
  `close_code`. Both carry `violations`, each with `rule`, `severity`,
  `message`, and — when the rule named the defect it found — `violation`, the
  catalogue id the `[violations]` config section tunes.
- `--min-severity info|warn|error` (default `info`): drop findings below the
  given severity from the report *and* from the exit-code decision — with
  `--min-severity error`, warn-level findings no longer fail CI. Stateful rules
  still see every transaction; only the reporting is gated.

The `--config` file is the same TOML used by `proxy-start`; `lint-captures` reads only the
`[rules]` toggles/severities, the `[violations]` overrides beside them, and the
`[general]` `ttl_seconds` / `max_history`
(used to size the replay's history window). The `listen`, `captures`, and
`[tls]` fields are ignored by `lint-captures`.

## Configuration File Structure

The configuration file is divided into three main sections: `[general]`, `[tls]`, and `[rules]`.

### General Configuration (Mandatory)

The `[general]` section configures the core proxy behavior.

```toml
[general]
listen = "127.0.0.1:3000"         # Address to listen on
captures = "captures.jsonl"       # Path to capture file
ttl_seconds = 300                 # How long to keep state records
captures_seed = false             # Seed state from captures file on startup
captures_include_body = false     # When true, captured bodies are included in the captures JSONL (base64). Default: false
max_body_bytes = 67108864         # Max body bytes buffered per request/response. Default: 64 MiB
max_connections = 1024            # Max simultaneous live TCP connections. Default: 1024
shutdown_timeout_seconds = 30     # Seconds to drain in-flight handlers on Ctrl-C. Default: 30
live_stream_enabled = false       # Serve the live capture SSE endpoint. Default: false
```

- **listen**: The IP address and port the proxy should bind to.
- **captures**: The file path where traffic logs (JSONL) will be appended.
- **ttl_seconds**: Time-to-live for stateful analysis records (e.g., tracking request frequency).
- **captures_seed**: When set to `true`, the proxy will load previous capture records from the captures file on startup and seed the state store. This enables:
  - Continuing analysis from previous proxy sessions (stateful rules will have access to "previous" transactions)
  - Setting up elaborate testing scenarios with mocked previous states
  - Default is `false` (disabled).
- **max_body_bytes**: Cap on the one body still buffered fully in memory — the WebSocket upgrade handshake request, which must be replayed upstream as a single buffer (default: 64 MiB). An over-limit handshake body is rejected with `413`, marked `request_body_over_limit`, and not captured. Since the streaming pipeline shipped, H1/H2/H3 request/response bodies are **not** bounded by this; they stream through, and only the captured copy is bounded (see `captures_max_body_bytes`).
- **captures_max_body_bytes**: Maximum number of body bytes captured into the transaction for lint rules and the captures file (default: 1 MiB). Bodies are forwarded in full regardless; only the captured copy is bounded to this prefix. When a body is larger, `request_body_over_limit` / `response_body_over_limit` mark the captured body as a truncated prefix, while `body_length` still records the real size. Rules that need the full body (e.g. multipart boundary checks, problem+json structure) skip content inspection on truncated bodies.
- **max_connections**: Maximum number of simultaneous live TCP connections the proxy will serve (default: 1024). Additional connections wait for a slot rather than being accepted unboundedly, bounding resource use under burst load.
- **shutdown_timeout_seconds**: On graceful shutdown (Ctrl-C), how many seconds to wait for in-flight handlers to drain before exiting anyway (default: 30). The capture file is flushed and fsynced as part of shutdown, so the last records are never truncated.
- **live_stream_enabled**: When `true`, the proxy serves a live capture stream at `GET /_lint_http/stream` — a [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) feed that pushes each transaction (one `data:` JSON event) as it commits, replacing `tail -f` on the captures file. Each event has the same JSON shape as a captures-file line (bodies included as base64 only when `captures_include_body` is set). Because it exposes every proxied transaction to anyone who can reach the proxy port, it is opt-in: when disabled (the default) the endpoint returns `404`. Watch it with `curl -N http://127.0.0.1:3000/_lint_http/stream` (reachable over HTTP/1.1 and HTTP/2, not HTTP/3).

### TLS Configuration (Mandatory)

The `[tls]` section configures HTTPS interception.

```toml
[tls]
enabled = true                    # Enable HTTPS interception
ca_cert_path = "ca.crt"           # Path to CA certificate (auto-generated if missing)
ca_key_path = "ca.key"            # Path to CA private key (auto-generated if missing)
passthrough_domains = []          # Domains to skip TLS interception
suppress_headers = []             # Headers to suppress from server responses
```

- **enabled**: Set to `true` to enable TLS interception. If `false`, the proxy will tunnel HTTPS traffic without inspection.
- **ca_cert_path**: Path to the Certificate Authority (CA) certificate. If it doesn't exist, it will be generated.
- **ca_key_path**: Path to the CA private key. **Keep this secure.**
- **passthrough_domains**: A list of domains (e.g., `["bank.com"]`) that should not be intercepted. Traffic to these domains will be tunneled opaque.
- **suppress_headers**: A list of **request** headers to remove before forwarding upstream (e.g., `["Authorization"]` to keep a credential off the wire while testing). The rules still see the header the client sent — suppression applies only to the copy the origin receives, so what this changes is the response, not the linting of the request.

### HTTP/3 Upstream (Optional)

By default the proxy forwards to origins over HTTP/1.1 or HTTP/2 (the hyper client). It can additionally forward the *proxy → origin* leg over **HTTP/3 (QUIC)** so that leg is exercised and linted like any other traffic. Selection is **capability-driven**: HTTP/3 is used for an origin when it is on the allowlist or has been discovered via `Alt-Svc`, and the proxy transparently falls back to HTTP/1.1/HTTP/2 when HTTP/3 is unavailable. These live in the `[general]` section and are all optional (the feature is off unless `h3_upstream_enabled = true`).

```toml
[general]
h3_upstream_enabled = false                       # Master switch. Default: false
h3_upstream_authorities = ["origin.example:443"]  # Origins always tried over H3 (pre-seeds discovery)
h3_upstream_denylist = ["legacy.example:443"]     # Origins that must never use H3
h3_upstream_trust_alt_svc = true                  # Learn H3 endpoints from origin Alt-Svc headers. Default: true
h3_upstream_bind = "[::]:0"                       # UDP bind address for the H3 client. Default: "[::]:0" (dual-stack)
h3_upstream_extra_ca_certs = []                   # Extra CA PEM files to trust for origin H3 endpoint certs
h3_upstream_connect_timeout_ms = 5000             # Connect + QUIC handshake budget. Default: 5000
h3_upstream_response_timeout_ms = 30000           # Response-head (first byte) budget. Default: 30000
h3_upstream_negative_ttl_seconds = 30             # Base backoff after an H3 failure. Default: 30
h3_upstream_pool_idle_ms = 25000                  # Idle time before a pooled H3 connection is evicted. Default: 25000
h3_upstream_pool_max = 256                        # Max pooled H3 connections (one per origin). Default: 256
```

- **h3_upstream_enabled**: Master switch. When `false` (default), every origin uses the HTTP/1.1/HTTP/2 client and none of the settings below have any effect.
- **h3_upstream_authorities**: Origin authorities (`host:port`) always attempted over HTTP/3. This pre-seeds selection — the *first* request to an origin cannot have learned `Alt-Svc` yet, so without an allowlist entry HTTP/3 is inherently second-connection-onward. The port is optional and defaults to `443`, and matching is case-insensitive, so `example.com` and `example.com:443` are equivalent.
- **h3_upstream_denylist**: Origin authorities that must **never** use HTTP/3, overriding both the allowlist and `Alt-Svc` discovery. Same `host[:port]` normalization as the allowlist.
- **h3_upstream_trust_alt_svc**: When `true` (default), an origin's `Alt-Svc: h3=...` response header adds an HTTP/3 route for that origin at runtime (honoring `ma`/`clear`). A discovered endpoint is only *used* once its certificate validates **for the origin authority** (RFC 7838 §2.1 / RFC 9114 §3.3) — a mismatched cert fails the handshake and the proxy falls back. Set `false` to route HTTP/3 solely from `h3_upstream_authorities`.
- **h3_upstream_bind**: The local UDP socket the HTTP/3 client binds. Default `"[::]:0"` — the IPv6 wildcard on an ephemeral port, which quinn makes dual-stack (it clears `only_v6` and maps an IPv4 peer to a v4-mapped address), so origins of either family are reachable. Pinning this to an IPv4 address makes IPv6-only origins unreachable over HTTP/3 — they fall back to HTTP/1.1/HTTP/2. Hosts without IPv6 fall back to the IPv4 wildcard automatically.
- **h3_upstream_extra_ca_certs**: Extra CA PEM files (private CAs) to trust when validating origin HTTP/3 endpoint certificates, layered on top of the system roots. Useful for an internal origin under test.
- **h3_upstream_connect_timeout_ms**: How long to wait for the QUIC connect + handshake before treating the attempt as failed and falling back to HTTP/1.1/HTTP/2 (default: 5000).
- **h3_upstream_response_timeout_ms**: How long to wait for the origin's **response head** (first byte) once the request has been sent (default: 30000). This is origin think-time, bounded separately from — and far more generously than — the connect timeout so a slow-but-healthy origin is not dropped. An idempotent, bodyless request that hits this timeout is retried on HTTP/1.1/HTTP/2 (RFC 9110 §9.2.2); anything else returns `502`.
- **h3_upstream_negative_ttl_seconds**: After a connect/handshake failure, an origin is not retried over HTTP/3 for this window (doubling per consecutive failure, capped), so a non-HTTP/3 origin is not probed on every request (default: 30). A successful HTTP/3 exchange clears the entry immediately. A response-head timeout does **not** negative-cache — the origin is healthy, just slow.
- **h3_upstream_pool_idle_ms**: How long a pooled HTTP/3 connection may sit idle before eviction (default: 25000). Kept below the QUIC idle timeout so only still-live connections are reused.
- **h3_upstream_pool_max**: Maximum pooled HTTP/3 connections, one per origin authority; the least-recently-used is evicted past this (default: 256).

Which leg served each request is recorded in the capture: `response.version` is `HTTP/3` when the origin leg used HTTP/3, or `HTTP/1.1`/`HTTP/2` when it fell back. Enable `debug`-level logging to see per-request selection (H3 chosen, negative-cache suppression, pool reuse vs. fresh connect, and fallbacks).

### Lint Rules Configuration

The `[rules]` section allows you to enable, disable, or configure specific lint rules. If a rule is omitted, it defaults to `false` (disabled).

Severity is **not** a rule-level key. A rule table carrying one is rejected at
startup, with a message naming the `[violations]` section below: every finding
reports at the severity its own defect carries, so a single scalar per rule
could only say the same thing about all of them.

```toml
[rules.cache_control_present]
enabled = true
```

#### Enabling Rules

Rules must be enabled via a TOML table with `enabled = true`. Example:

```toml
# Client Rules
[rules.accept_encoding_present]
enabled = true
```

#### Configurable Rules

Some rules support additional configuration options beyond simple enable/disable. Use TOML tables to configure these rules.

```toml
# Configure clear_site_data_present with custom logout paths
[rules.clear_site_data_present]
enabled = true
paths = ["/logout", "/signout", "/auth/logout", "/api/v1/logout"]
```

See [Rules Documentation](rules.md) for details on each rule and their configuration options.

### Violation Overrides

A rule is the unit of analysis; a *violation* is the unit of report — one named
defect a rule may find. A rule that checks four things reports four violations,
and the `[violations]` section is where each of them is tuned separately.

Every violation carries a default severity in the catalogue and reports unless
you say otherwise, so this section is optional and mostly stays empty: write a
table only to disagree with a default.

The shape — every id below is a real one, and `config_example.toml` lists the rest:

```toml
# The rule is on...
[rules.strict_transport_security_valid]
enabled = true

# ...this one defect it reports is an error, where the rest keep whatever
# the catalogue gives them...
[violations.strict_transport_security_max_age_missing]
severity = "error"

# ...and this one is not reported at all.
[violations.strict_transport_security_directive_duplicated]
enabled = false
```

`severity` and `enabled` are the only keys, and a table that is written must set
at least one of them — a section that sets nothing is a section that does
nothing, and both are rejected at startup. Every violation id and its default is
listed in `config_example.toml` and indexed in `docs/violations.md`, where each
one links to a page naming the sentences it enforces and the rules that report
it; a table naming an id that does not exist is rejected here too, the same way
an unknown rule id is.

`enabled = false` drops that defect's findings and leaves the rule's other
defects reporting. **One thing it does not do**: on a transaction where the
switched-off defect fired, it does not bring a *different* defect of the same
rule into view. Most rules report their first finding and stop, so the rule
never looked further — that truncation is the rule's own, and it was there
before anything was switched off. What you lose is the defect you switched off,
which is what you asked to lose.

**Turning a whole rule down means writing one table per defect it reports**,
where a single `[rules.<id>] severity` used to do it. That is the cost of the
split and it is a real one: `docs/rules/<id>.md` lists the defects a rule
reports, each linking to its own page under `docs/violations/`, and
`config_example.toml` lists every id with its default. To quiet a rule wholesale
without listing them, `[rules.<id>] enabled = false` still switches it off, and
`--min-severity` still filters the report.

A finding carries both names: `rule` and `violation`, printed as `rule/defect`.
Older captures carry `rule` alone. Both names have a page: the rule's says what
analysis ran, the defect's says what it found and what else reports it.
