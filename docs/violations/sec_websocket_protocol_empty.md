<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_protocol_empty

Sec-WebSocket-Protocol is written with no subprotocol in it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §4.2.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2): Sending the Server's Opening Handshake — what a server sends if it accepts, the five things it sends instead if it does not, and how `Sec-WebSocket-Accept`, `/subprotocol/` and `/extensions/` are derived from the request

## Configuration

```toml
[violations.sec_websocket_protocol_empty]
# Sec-WebSocket-Protocol is written with no subprotocol in it
severity = "error"
```

## Reported By

- [websocket_handshake_valid](../rules/websocket_handshake_valid.md)
