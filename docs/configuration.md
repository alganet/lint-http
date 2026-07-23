<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Configuration

`lint-http` is configured using a TOML file. You provide this file to the `run`
subcommand using the `--config` CLI argument.

## Command-Line Options

`lint-http` uses subcommands:

- `run --config <PATH>`: Start the intercepting proxy. `<PATH>` is the TOML
  configuration file (mandatory).
- `lint --config <PATH> [--format text|json] [--min-severity info|warn|error]
  <CAPTURES>`: Lint a recorded capture file offline (see below).
- `rules list [--format text|json] [--config <PATH>]`: List every rule and its
  metadata (id, scope, title, and — in JSON — description, spec references, and
  documentation examples). No config or proxy needed; it prints the static
  catalogue. With `--config`, each rule is additionally annotated with whether
  that config enables it (an `enabled`/`disabled` text column, an `enabled`
  JSON field).
- `gendocs [--out <DIR>]`: Regenerate the per-rule docs (`rules.md` index +
  `rules/<id>.md`) from rule metadata under `<DIR>` (default `docs`).
- `-h, --help`: Print help (works on the binary and on each subcommand)
- `-V, --version`: Print version

Example:

```bash
lint-http run --config config.toml
```

For backwards compatibility, a bare `lint-http --config config.toml` is still
accepted as a deprecated alias for `run` (it prints a warning); prefer the
`run` form.

## Linting recorded captures

`lint-http lint --config <PATH> <CAPTURES>` replays a JSONL capture file (the
`captures` file the proxy writes) through the rule engine without running a
proxy — the CI story: lint recorded HTTP fixtures offline.

```bash
lint-http lint --config config.toml captures.jsonl
```

It replays the records in file order. Each transaction is linted against the
history of prior transactions, exactly as it would be live, so stateful rules
work. WebSocket session records are replayed per-message through the protocol
rules (the frame events the live relay emits are rebuilt from the captured
message metadata); the session's live-recorded `violations` field is ignored —
replay re-lints under the current config. It prints one block per offending
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
  `message`.
- `--min-severity info|warn|error` (default `info`): drop findings below the
  given severity from the report *and* from the exit-code decision — with
  `--min-severity error`, warn-level findings no longer fail CI. Stateful rules
  still see every transaction; only the reporting is gated.

The `--config` file is the same TOML used by `run`; `lint` reads only the
`[rules]` toggles/severities and the `[general]` `ttl_seconds` / `max_history`
(used to size the replay's history window). The `listen`, `captures`, and
`[tls]` fields are ignored by `lint`.

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
- **suppress_headers**: A list of response headers to remove before sending to the client (e.g., `["Strict-Transport-Security"]` to prevent HSTS issues during testing).

### HTTP/3 Upstream (Optional)

By default the proxy forwards to origins over HTTP/1.1 or HTTP/2 (the hyper client). It can additionally forward the *proxy → origin* leg over **HTTP/3 (QUIC)** so that leg is exercised and linted like any other traffic. Selection is **capability-driven**: HTTP/3 is used for an origin when it is on the allowlist or has been discovered via `Alt-Svc`, and the proxy transparently falls back to HTTP/1.1/HTTP/2 when HTTP/3 is unavailable. These live in the `[general]` section and are all optional (the feature is off unless `h3_upstream_enabled = true`).

```toml
[general]
h3_upstream_enabled = false                       # Master switch. Default: false
h3_upstream_authorities = ["origin.example:443"]  # Origins always tried over H3 (pre-seeds discovery)
h3_upstream_denylist = ["legacy.example:443"]     # Origins that must never use H3
h3_upstream_trust_alt_svc = true                  # Learn H3 endpoints from origin Alt-Svc headers. Default: true
h3_upstream_bind = "0.0.0.0:0"                    # UDP bind address for the H3 client. Default: "0.0.0.0:0"
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
- **h3_upstream_bind**: The local UDP socket the HTTP/3 client binds. Default `"0.0.0.0:0"` (any interface, ephemeral port).
- **h3_upstream_extra_ca_certs**: Extra CA PEM files (private CAs) to trust when validating origin HTTP/3 endpoint certificates, layered on top of the system roots. Useful for an internal origin under test.
- **h3_upstream_connect_timeout_ms**: How long to wait for the QUIC connect + handshake before treating the attempt as failed and falling back to HTTP/1.1/HTTP/2 (default: 5000).
- **h3_upstream_response_timeout_ms**: How long to wait for the origin's **response head** (first byte) once the request has been sent (default: 30000). This is origin think-time, bounded separately from — and far more generously than — the connect timeout so a slow-but-healthy origin is not dropped. An idempotent, bodyless request that hits this timeout is retried on HTTP/1.1/HTTP/2 (RFC 9110 §9.2.2); anything else returns `502`.
- **h3_upstream_negative_ttl_seconds**: After a connect/handshake failure, an origin is not retried over HTTP/3 for this window (doubling per consecutive failure, capped), so a non-HTTP/3 origin is not probed on every request (default: 30). A successful HTTP/3 exchange clears the entry immediately. A response-head timeout does **not** negative-cache — the origin is healthy, just slow.
- **h3_upstream_pool_idle_ms**: How long a pooled HTTP/3 connection may sit idle before eviction (default: 25000). Kept below the QUIC idle timeout so only still-live connections are reused.
- **h3_upstream_pool_max**: Maximum pooled HTTP/3 connections, one per origin authority; the least-recently-used is evicted past this (default: 256).

Which leg served each request is recorded in the capture: `response.version` is `HTTP/3` when the origin leg used HTTP/3, or `HTTP/1.1`/`HTTP/2` when it fell back. Enable `debug`-level logging to see per-request selection (H3 chosen, negative-cache suppression, pool reuse vs. fresh connect, and fallbacks).

### Lint Rules Configuration

The `[rules]` section allows you to enable, disable, or configure specific lint rules. If a rule is omitted, it defaults to `false` (disabled).

Severity: Each rule table must include a `severity` key. Allowed values are `"info"`, `"warn"`, and `"error"`. When present, this value is used in emitted `Violation` records and in captures. Example:

```toml
[rules.server_cache_control_present]
enabled = true
severity = "warn"
```

#### Enabling Rules

Rules must be enabled via a TOML table with `enabled = true`. Example:

```toml
# Client Rules
[rules.client_accept_encoding_present]
enabled = true
severity = "info"
```

#### Configurable Rules

Some rules support additional configuration options beyond simple enable/disable. Use TOML tables to configure these rules.

```toml
# Configure server_clear_site_data with custom logout paths
[rules.server_clear_site_data]
enabled = true
paths = ["/logout", "/signout", "/auth/logout", "/api/v1/logout"]
```

See [Rules Documentation](rules.md) for details on each rule and their configuration options.
