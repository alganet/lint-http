<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# base64_pad_bits_invalid

Final base64 symbol carries bits a conforming encoder zeroes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 4648 §3.5](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5): Canonical encoding — the discarded bits of a final symbol MUST be zero in what an encoder writes, and a decoder MAY reject an encoding where they are not

## Configuration

```toml
[violations.base64_pad_bits_invalid]
# Final base64 symbol carries bits a conforming encoder zeroes
severity = "info"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
