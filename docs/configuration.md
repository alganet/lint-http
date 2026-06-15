<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Configuration

`lint-http` is configured using a TOML file. You must provide this file using the `--config` CLI argument.

## Command-Line Options

- `--config <PATH>`: Path to TOML configuration file (mandatory)
- `-h, --help`: Print help
- `-V, --version`: Print version

Example:

```bash
lint-http --config config.toml
```

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
```

- **listen**: The IP address and port the proxy should bind to.
- **captures**: The file path where traffic logs (JSONL) will be appended.
- **ttl_seconds**: Time-to-live for stateful analysis records (e.g., tracking request frequency).
- **captures_seed**: When set to `true`, the proxy will load previous capture records from the captures file on startup and seed the state store. This enables:
  - Continuing analysis from previous proxy sessions (stateful rules will have access to "previous" transactions)
  - Setting up elaborate testing scenarios with mocked previous states
  - Default is `false` (disabled).
- **max_body_bytes**: Maximum number of body bytes the proxy will buffer per request or response (default: 64 MiB). Over-limit request bodies are rejected with `413`; over-limit response bodies abort the exchange with `502`. Either way the captured transaction is marked with `request_body_over_limit` / `response_body_over_limit` and the body itself is not captured.
- **captures_max_body_bytes**: Maximum number of body bytes captured into the transaction for lint rules and the captures file (default: 1 MiB). Bodies are forwarded in full regardless; only the captured copy is bounded to this prefix. When a body is larger, `request_body_over_limit` / `response_body_over_limit` mark the captured body as a truncated prefix, while `body_length` still records the real size. Rules that need the full body (e.g. multipart boundary checks, problem+json structure) skip content inspection on truncated bodies.
- **max_connections**: Maximum number of simultaneous live TCP connections the proxy will serve (default: 1024). Additional connections wait for a slot rather than being accepted unboundedly, bounding resource use under burst load.
- **shutdown_timeout_seconds**: On graceful shutdown (Ctrl-C), how many seconds to wait for in-flight handlers to drain before exiting anyway (default: 30). The capture file is flushed and fsynced as part of shutdown, so the last records are never truncated.

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
