<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http

HTTP forward proxy that captures request/response metadata and runs lint rules.

## Installation

```bash
cargo install --path .
```

## Usage

Start the proxy:

```bash
lint-http --listen 127.0.0.1:3000 --captures captures.jsonl
```

Point your HTTP client to `http://127.0.0.1:3000`. The proxy forwards requests and appends capture records to `captures.jsonl`.

## Configuration

Create a `config.toml` to toggle rules:

```toml
[rules]
cache-control-present = true
etag-or-last-modified = false
x-content-type-options = true
```

Run with config:

```bash
lint-http --listen 127.0.0.1:3000 --captures captures.jsonl --config config.toml
```

## Rules

- **cache-control-present**: Warns if 200 responses lack Cache-Control header
- **etag-or-last-modified**: Suggests ETag or Last-Modified for validation
- **x-content-type-options**: Recommends X-Content-Type-Options: nosniff

## License

ISC
