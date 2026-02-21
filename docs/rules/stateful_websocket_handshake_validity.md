<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket handshake validity

## Description

When a client requests an HTTP upgrade to the WebSocket protocol, the server
must reply with a precise handshake response.  This rule inspects the
request/response pair and ensures the response follows the opening-handshake
rules in [RFC 6455 §4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4):

* the status code is `101 Switching Protocols`;
* `Connection: Upgrade` and `Upgrade: websocket` headers are present;
* the `Sec-WebSocket-Accept` header value is the SHA‑1 + base64 digest of the
  client's `Sec-WebSocket-Key` concatenated with the magic GUID.

Failure to mirror the client's key, omit required tokens, or use the wrong
status code indicates a malformed handshake and may prevent the WebSocket
connection from being established.

## Specifications

- [RFC 6455 §4.2.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2) — “Opening Handshake”, calculate `Sec-WebSocket-Accept`.
- [RFC 9110 §9.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.5) — rules for `Connection` and `Upgrade` header interaction during protocol upgrades.

## Configuration

```toml
[rules.stateful_websocket_handshake_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good
```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

```

### ❌ Bad (mismatched accept)
```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: WRONG==

```