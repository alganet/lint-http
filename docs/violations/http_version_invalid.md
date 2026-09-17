<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http_version_invalid

A protocol version is below the floor the exchange requires

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.http_version_invalid]
# A protocol version is below the floor the exchange requires
severity = "warn"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
