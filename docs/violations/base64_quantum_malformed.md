<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# base64_quantum_malformed

Value is not a whole number of base64 groups

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4): Base 64 Encoding — the 24-bit group written as four characters, and the padding that completes a final group of fewer bits

## Configuration

```toml
[violations.base64_quantum_malformed]
# Value is not a whole number of base64 groups
severity = "warn"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
