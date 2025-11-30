# lint-http

HTTP forward proxy with linting and capture capabilities.

`lint-http` intercepts HTTP requests and responses, checks for adherence to best practices, and captures detailed traffic logs. It is designed to help developers identify missing headers and other common issues in their HTTP traffic.

## Features

- **Traffic Capture**: Logs full request and response details (method, URI, status, headers, timing) to a JSONL file.
- **Linting**: Automatically checks for violations of HTTP best practices.
- **Configuration**: Enable or disable specific lint rules via a TOML configuration file.
- **Proxy**: Functions as a standard HTTP forward proxy, compatible with tools like `curl`, browsers, and other HTTP clients.

## Installation

To install `lint-http` from source:

```bash
cargo install --path .
```

## Usage

Start the proxy server:

```bash
lint-http
```

By default, the server listens on `127.0.0.1:3000` and writes captures to `captures.jsonl`.

### Options

- `--listen <ADDR>`: Specify the address to listen on (default: `127.0.0.1:3000`).
- `--captures <PATH>`: Specify the path to the capture file (default: `captures.jsonl`).
- `--config <PATH>`: Specify the path to a TOML configuration file.

Example:

```bash
lint-http --listen 127.0.0.1:8080 --captures my_traffic.jsonl --config rules.toml
```

## Configuration

You can configure `lint-http` using a TOML file. The `[rules]` section allows you to enable or disable specific rules.

Example `config.toml`:

```toml
[rules]
server_cache_control_present = true
client_user_agent_present = false
```

## Rules

See [docs/rules](docs/rules) for a list of available lint rules.
