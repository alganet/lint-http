<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_version_conflicting

Sec-WebSocket-Version advertises the version the request asked for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §11.3.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.5): The field's registration — when a server sends it, and that it holds the versions the server supports, which is what a list holding the requested one contradicts

## Configuration

```toml
[violations.sec_websocket_version_conflicting]
# Sec-WebSocket-Version advertises the version the request asked for
severity = "warn"
```

## Reported By

- [sec_websocket_version_advertised](../rules/sec_websocket_version_advertised.md)
