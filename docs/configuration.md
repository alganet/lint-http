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
```

- **listen**: The IP address and port the proxy should bind to.
- **captures**: The file path where traffic logs (JSONL) will be appended.
- **ttl_seconds**: Time-to-live for stateful analysis records (e.g., tracking request frequency).
- **captures_seed**: When set to `true`, the proxy will load previous capture records from the captures file on startup and seed the state store. This enables:
  - Continuing analysis from previous proxy sessions (stateful rules will have access to "previous" transactions)
  - Setting up elaborate testing scenarios with mocked previous states
  - Default is `false` (disabled).

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
