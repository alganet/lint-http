<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http

⚠️ **Early stage, experimental and incomplete.** ⚠️

**A TLS-terminating HTTP/HTTPS forward proxy that lints traffic and writes captures.** 🔧

lint-http inspects HTTP(S) traffic, runs protocol best-practice checks (rules), and writes detailed JSONL captures for debugging and analysis. It's intended as a development and testing tool — not for production use.

---

## Highlights

- TLS interception using Rust-native stacks (rustls / tokio-rustls / hyper-rustls)
- HTTP/2 and HTTP/1.1 support (via ALPN)
- JSONL traffic captures (`captures.jsonl`) with request/response metadata + timing
- Configurable, stateful lint rules (enable/disable via TOML)
- Easy to use with curl, browsers, and other HTTP clients

## Quick start — run locally

1) Build and run (recommended for development):

```bash
cargo run -- --config config_example.toml
```

2) Basic HTTP usage:

```bash
# use the proxy (example listens on 127.0.0.1:3000)
curl -x http://localhost:3000 http://example.com
```

3) HTTPS interception (trust the generated CA locally):

```bash
# Download the CA cert exposed by the running proxy
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt
# Tell your client to trust `lint-http-ca.crt` and use the proxy for HTTPS
curl -x http://localhost:3000 --cacert lint-http-ca.crt https://example.com
```

Notes:
- The proxy uses rustls; no system OpenSSL dependency is required for basic operation.
- See `config_example.toml` for an example configuration.

## Configuration

The proxy is configured via a TOML file passed with `--config`.

```bash
lint-http --config config.toml
```

Refer to `docs/configuration.md` for full options, including TLS settings and rule configuration.

Example snippet:

```toml
[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300

[tls]
enabled = true
```

## Lint rules

Rules cover common client and server best practices (e.g., `User-Agent` presence, `Cache-Control`, `ETag`, connection reuse). Rules are documented in `docs/rules/` and listed in `docs/rules.md`.

## Capture format

Captures are written as JSON Lines; each line is an `HttpTransaction` JSON object containing:
- unique `id`, `timestamp`
- `client` metadata (ip, user-agent)
- `request` (method, uri, headers)
- `response` (status, headers)
- `timing` (duration)
- `violations` (rule id, severity, message)

Example (abbreviated):

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-11-30T10:30:00Z",
  "client": { "ip": "127.0.0.1", "user_agent": "test-client" },
  "request": {
    "method": "GET",
    "uri": "https://example.com/api/data",
    "headers": { ... }
  },
  "response": {
    "status": 200,
    "headers": { ... }
  },
  "timing": { "duration_ms": 145 },
  "violations": [
    {
      "rule": "server_cache_control_present",
      "severity": "warn",
      "message": "Response is missing Cache-Control header"
    }
  ]
}
```

## Development

Run tests and linters locally:

```bash
# run tests
cargo test

# run lint (clippy alias in .cargo/config.toml)
cargo lint

# coverage (alias in .cargo/config.toml)
cargo coverage
```

See `.cargo/config.toml` for configured aliases (coverage/lint).

## Security notice

lint-http is a debugging tool — do not use in production.
- The CA private key can decrypt intercepted HTTPS traffic; keep it private
- Only use on trusted networks and machines

## Contributing & license

Contributions are welcome — see `.github/CONTRIBUTING.md` for guidelines. The project is licensed under the ISC license (see `LICENSE`).
