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
# Start the proxy
lint-http

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

### Command-Line Options

- `--listen <ADDR>`: Address to listen on (default: `127.0.0.1:3000`)
- `--captures <PATH>`: Path to capture file (default: `captures.jsonl`)
- `--config <PATH>`: Path to TOML configuration file

Example:

```bash
lint-http --listen 0.0.0.0:8080 --captures traffic.jsonl --config rules.toml
```

### Configuration File

Create a `config.toml` file to customize behavior:

```toml
# State Configuration
[state]
ttl_seconds = 300                 # How long to keep state records (default: 300)

# TLS Configuration
[tls]
enabled = true                    # Enable HTTPS interception
ca_cert_path = "ca.crt"           # Path to CA certificate (auto-generated if missing)
ca_key_path = "ca.key"            # Path to CA private key (auto-generated if missing)

# Lint Rules Configuration
[rules]
# Client Rules
client_accept_encoding_present = true   # Check for Accept-Encoding header
client_user_agent_present = true        # Check for User-Agent header
client_cache_respect = true             # Verify conditional requests for cached resources
connection_efficiency = true            # Track requests per connection

# Server Rules
server_cache_control_present = true           # Verify Cache-Control headers
server_etag_or_last_modified = true           # Check for ETag or Last-Modified
server_x_content_type_options = true          # Verify X-Content-Type-Options: nosniff
```

See [`config_example.toml`](config_example.toml) for a complete example.

## TLS/HTTPS Setup

### Installing the CA Certificate

For HTTPS interception to work, you need to trust the auto-generated CA certificate:

#### Linux
```bash
# Download the certificate
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt

# Install it
sudo cp lint-http-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

#### macOS
```bash
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt
sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain lint-http-ca.crt
```

#### Windows (PowerShell as Administrator)
```powershell
Invoke-WebRequest http://localhost:3000/_lint_http/cert -OutFile lint-http-ca.crt
Import-Certificate -FilePath lint-http-ca.crt `
  -CertStoreLocation Cert:\\LocalMachine\\Root
```

### Using with curl (without system-wide installation)

```bash
# Download CA cert
curl http://localhost:3000/_lint_http/cert > ca.crt

# Use --cacert for HTTPS requests
curl -x http://localhost:3000 --cacert ca.crt https://example.com
```

## Lint Rules

`lint-http` includes several built-in rules organized by category:

### Client Rules

- **client_accept_encoding_present**: Checks if Accept-Encoding header is present
- **client_user_agent_present**: Checks if User-Agent header is present  
- **client_cache_respect**: Verifies clients send conditional headers (If-None-Match/If-Modified-Since) when re-requesting cached resources
- **connection_efficiency**: Tracks requests per connection and warns about inefficient connection reuse

### Server Rules

- **server_cache_control_present**: Checks for Cache-Control header on cacheable responses
- **server_etag_or_last_modified**: Checks for ETag or Last-Modified headers
- **server_x_content_type_options**: Checks for X-Content-Type-Options: nosniff

See [docs/rules](docs/rules) for detailed documentation on each rule.

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
