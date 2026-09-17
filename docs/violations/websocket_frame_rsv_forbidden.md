<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_rsv_forbidden

A reserved bit is set and no extension was negotiated to give it a meaning

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2): Base Framing Protocol — the three reserved bits, their width, the conditional MUST on the sender and the MUST-fail on the recipient

## Configuration

```toml
[violations.websocket_frame_rsv_forbidden]
# A reserved bit is set and no extension was negotiated to give it a meaning
severity = "error"
```

## Reported By

- [websocket_frame_rsv_bits](../rules/websocket_frame_rsv_bits.md)
