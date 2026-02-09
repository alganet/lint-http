<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_sec_websocket_headers_consistency

## Description

For `GET` requests with `Upgrade: websocket`, validate that the WebSocket client handshake request includes required headers and well-formed values:

- `Connection` header includes the `Upgrade` token.
- `Sec-WebSocket-Version` is present and equals `13`.
- `Sec-WebSocket-Key` is present and decodes from base64 to 16 bytes (nonce).

This rule helps detect malformed WebSocket upgrade requests that will be rejected by compliant servers (RFC 6455).

## Specifications

- [RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1) — Client Handshake: request must be GET and include `Upgrade: websocket` and `Connection: Upgrade`.

- [RFC 6455 §4.2.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1) — `Sec-WebSocket-Key` must be a base64-encoded 16-byte nonce; `Sec-WebSocket-Version` expected value is `13`.

## Configuration

Enable or disable the rule and set severity in `config.toml`.

```toml
[rules.client_sec_websocket_headers_consistency]
enabled = false
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

### ❌ Bad — missing Sec-WebSocket-Key

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
```

### ❌ Bad — invalid Sec-WebSocket-Version

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 8
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```
