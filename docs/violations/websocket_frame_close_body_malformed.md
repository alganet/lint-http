<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_close_body_malformed

A Close body is too short to hold the status code it opens with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 6455 §5.5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1): Close — the body is optional, a body that exists opens with a two-byte status code, and a sender's own Close ends what it may send

## Configuration

```toml
[violations.websocket_frame_close_body_malformed]
# A Close body is too short to hold the status code it opens with
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
