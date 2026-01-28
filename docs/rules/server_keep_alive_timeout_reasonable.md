<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_keep_alive_timeout_reasonable

## Description

When a `Keep-Alive` header includes a `timeout` directive, this rule checks that the `timeout` value is reasonable. The `timeout` value should be a non-negative integer greater than zero and not unreasonably large (e.g., not several hours). `Keep-Alive` is a legacy header used to tune connection persistence; conservative, reasonable values help prevent resource exhaustion on servers and clients.

## Specifications

- [RFC 7230 §6.7 - Connection management and the `Keep-Alive` discussion](https://www.rfc-editor.org/rfc/rfc7230.html#section-6.7) — `Keep-Alive` is a legacy header and must be treated conservatively; this rule validates `timeout` semantics only.

## Configuration

This rule requires a `max_timeout_seconds` integer in your rule table (no defaults).

```toml
[rules.server_keep_alive_timeout_reasonable]
enabled = true
severity = "warn"
max_timeout_seconds = 3600
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Keep-Alive: timeout=30, max=100
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Keep-Alive: timeout=0
```

```http
HTTP/1.1 200 OK
Keep-Alive: timeout=999999
```

```http
HTTP/1.1 200 OK
Keep-Alive: timeout="60"   # quoted numeric values are invalid
```
