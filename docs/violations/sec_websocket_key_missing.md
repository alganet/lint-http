<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_key_missing

WebSocket handshake carries no Sec-WebSocket-Key

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1): Client Requirements — the numbered list this rule measures: GET, HTTP version at least 1.1, `Upgrade: websocket`, the `Upgrade` connection-option, the `Sec-WebSocket-Key` nonce, `Sec-WebSocket-Version: 13`, and `Sec-WebSocket-Protocol`'s non-empty unique `token` members

## Configuration

```toml
[violations.sec_websocket_key_missing]
# WebSocket handshake carries no Sec-WebSocket-Key
severity = "error"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
