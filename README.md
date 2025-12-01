<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http

**HTTP/HTTPS forward proxy with linting and capture capabilities.**

`lint-http` intercepts HTTP and HTTPS traffic, checks for adherence to best practices, and captures detailed traffic logs. It functions as a TLS-terminating proxy with on-the-fly certificate generation, making it ideal for debugging and analyzing encrypted traffic during development.

## Features

- 🔒 **TLS/HTTPS Interception**: Full HTTPS traffic inspection with automatic certificate generation
- 🌐 **HTTP/2 Support**: Complete HTTP/2 and HTTP/1.1 protocol support via ALPN
- 📊 **Traffic Capture**: Logs request/response details (method, URI, status, headers, timing) to JSONL
- ✅ **Smart Linting**: Automatically checks HTTP traffic for best practice violations
- 📝 **Stateful Analysis**: Tracks client behavior across requests for cache validation and connection efficiency
- ⚙️ **Configurable Rules**: Enable/disable specific lint rules via TOML configuration
- 🔌 **Universal Proxy**: Compatible with curl, browsers, and any HTTP client

## Installation

### From Source

```bash
cargo install --path .
```

### Requirements

- Rust 1.70 or later
- OpenSSL (for native-tls support)

## Quick Start

### Basic HTTP Proxy

```bash
# Start the proxy (requires a configuration file)
lint-http --config config.toml

# Use with curl
curl -x http://localhost:3000 http://example.com
```

### HTTPS Proxy with TLS Interception

```bash
# 1. Start proxy with TLS enabled
lint-http --config config_example.toml

# 2. Download and trust the CA certificate
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt

# 3. Use the proxy with HTTPS
curl -x http://localhost:3000 --cacert lint-http-ca.crt https://example.com

# 4. HTTP/2 is fully supported
curl -x http://localhost:3000 --cacert lint-http-ca.crt --http2 https://www.google.com
```

## Configuration

`lint-http` is configured via a TOML file provided with the `--config` argument.

```bash
lint-http --config config.toml
```

For detailed configuration options, including **TLS setup** and **General settings**, see [docs/configuration.md](docs/configuration.md).

### Quick Example

```toml
[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300

[tls]
enabled = true
# ... see docs for full TLS config
```

## Lint Rules

`lint-http` checks for various client and server best practices, such as:

- **Client**: `User-Agent`, `Accept-Encoding`, Connection reuse, Cache respect.
- **Server**: `Cache-Control`, `ETag`, Security headers.

For a complete list of rules and their explanations, see [docs/rules.md](docs/rules.md).


## Capture Format

Captures are written as JSONL (JSON Lines) to the specified file:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-11-30T10:30:00Z",
  "method": "GET",
  "uri": "https://example.com/api/data",
  "status": 200,
  "request_headers": {...},
  "response_headers": {...},
  "duration_ms": 145,
  "violations": [
    {
      "rule": "server_cache_control_present",
      "severity": "warning",
      "message": "Response is missing Cache-Control header"
    }
  ]
}
```

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo coverage

# Coverage: 81.66% (383/469 lines)
```

### Project Structure

- `src/proxy.rs` - HTTP/HTTPS proxy implementation with TLS support
- `src/ca.rs` - Certificate authority for dynamic cert generation
- `src/lint.rs` - Lint rule evaluation engine
- `src/rules/` - Individual lint rule implementations
- `src/state.rs` - Stateful analysis across requests
- `src/capture.rs` - Traffic capture to JSONL
- `src/config.rs` - Configuration file parsing

## Security Considerations

⚠️ **WARNING**: `lint-http` is a development and debugging tool. **Never use in production environments.**

- The CA certificate private key provides full access to decrypt intercepted HTTPS traffic
- Never share or distribute the `ca.key` file
- Regularly rotate the CA certificate if used over extended periods
- Only use on networks you control

## License

ISC License - See LICENSE file for details

## Contributing

Contributions welcome! See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.
