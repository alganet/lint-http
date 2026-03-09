<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket Frame Opcode Sequence

## Description

Validates message-level opcode sequencing rules for WebSocket frames observed
during relay.  This rule inspects each frame event and checks:

* **Reserved opcodes** (3-7, 11-15) must not appear without a negotiated
  extension (RFC 6455 §5.2).
* **Control frame payload limit** — Close (8), Ping (9), and Pong (10) frames
  must not exceed 125 bytes of payload data (RFC 6455 §5.5).
* **Data after Close** — once a Close frame has been sent in a given direction,
  no further data frames (Text=1, Binary=2) should follow in that same
  direction (RFC 6455 §5.5.1).

## Specifications

- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2) — Base Framing Protocol, opcode definitions.
- [RFC 6455 §5.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5) — Control Frames, payload length constraint.
- [RFC 6455 §5.5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1) — Close frame semantics and half-close behaviour.

## Configuration

```toml
[rules.stateful_websocket_frame_opcode_sequence]
enabled = true
severity = "warn"
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

# After upgrade, valid frame sequence:
# Client -> Server: opcode=1 (Text), 42 bytes
# Server -> Client: opcode=1 (Text), 100 bytes
# Client -> Server: opcode=8 (Close), 2 bytes
# Server -> Client: opcode=8 (Close), 2 bytes
```

### ❌ Bad (reserved opcode)

```http
# After WebSocket upgrade, client sends reserved opcode:
# Client -> Server: opcode=5, 10 bytes
# Opcode 5 is reserved (RFC 6455 §5.2)
```

### ❌ Bad (control frame too large)

```http
# After WebSocket upgrade, client sends oversized Ping:
# Client -> Server: opcode=9 (Ping), 200 bytes
# Control frames must not exceed 125 bytes (RFC 6455 §5.5)
```

### ❌ Bad (data after close)

```http
# After WebSocket upgrade, client sends data after Close:
# Client -> Server: opcode=8 (Close), 2 bytes
# Client -> Server: opcode=1 (Text), 50 bytes
# No data frames after Close in same direction (RFC 6455 §5.5.1)
```
