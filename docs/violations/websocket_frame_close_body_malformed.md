<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_close_body_malformed

A Close body is too short to hold the status code it opens with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §5.5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1): Close — the body is optional, a body that exists opens with a two-byte status code, and a sender's own Close ends what it may send

## Configuration

```toml
[violations.websocket_frame_close_body_malformed]
# A Close body is too short to hold the status code it opens with
severity = "warn"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
