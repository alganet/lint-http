<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful 101 Switching Protocols

## Description

Validates that `101 Switching Protocols` responses follow correct HTTP upgrade semantics. The rule checks:

- The client must have requested the upgrade via the `Upgrade` header; unsolicited 101 responses are a protocol violation.
- The protocol chosen in the response `Upgrade` header must match one offered by the client.
- 101 must not be sent for HTTP/1.0 requests (Upgrade is an HTTP/1.1+ mechanism), or over HTTP/2 or HTTP/3 where the Upgrade mechanism is not supported.
- After a successful 101 exchange, no further HTTP messages should appear on the same connection — the connection has been handed off to the upgraded protocol.

## Specifications

- [RFC 9110 §15.2.2 — 101 Switching Protocols](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2)
- [RFC 9110 §7.8 — Upgrade](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)
- [RFC 9113 §8.6 — The CONNECT Method (HTTP/2 forbids 101)](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6)
- [RFC 9114 §4.1 — HTTP Message Exchanges (HTTP/3 forbids 101)](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)

## Configuration

```toml
[rules.stateful_101_switching_protocols]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — client requests upgrade and server agrees

```http
> GET /chat HTTP/1.1
> Upgrade: websocket
> Connection: Upgrade

< HTTP/1.1 101 Switching Protocols
< Upgrade: websocket
< Connection: Upgrade
```

### ✅ Good — server declines upgrade (non-101 response)

```http
> GET /resource HTTP/1.1
> Upgrade: h2c
> Connection: Upgrade

< HTTP/1.1 200 OK
```

### ❌ Bad — unsolicited 101 (no Upgrade in request)

```http
> GET /resource HTTP/1.1

< HTTP/1.1 101 Switching Protocols
< Upgrade: websocket
```

### ❌ Bad — protocol mismatch

```http
> GET /chat HTTP/1.1
> Upgrade: websocket
> Connection: Upgrade

< HTTP/1.1 101 Switching Protocols
< Upgrade: h2c
< Connection: Upgrade
```

### ❌ Bad — 101 over HTTP/2

```http
> GET /chat HTTP/2
> Upgrade: websocket

< HTTP/2 101 Switching Protocols
< Upgrade: websocket
```

### ❌ Bad — HTTP traffic after 101 on the same connection

```http
// previous transaction on this connection: 101 upgrade to websocket

> GET /other HTTP/1.1

< HTTP/1.1 200 OK
```
