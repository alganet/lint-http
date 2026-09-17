<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# upgrade_101_missing

A 101 response carries no Upgrade field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §15.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2): 101 Switching Protocols — the status code is a change in the application protocol being used on this connection, and the response MUST generate an `Upgrade` field naming the protocol(s) in effect after it

## Configuration

```toml
[violations.upgrade_101_missing]
# A 101 response carries no Upgrade field
severity = "error"
```

## Reported By

- [status_101_switching_protocols](../rules/status_101_switching_protocols.md)
- [websocket_handshake_valid](../rules/websocket_handshake_valid.md)
