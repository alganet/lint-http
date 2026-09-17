<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_control_fragmentation_forbidden

A control frame is fragmented

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §5.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.4): Fragmentation — what a fragmented message is made of, the MUST NOT against fragmenting a control frame stated in its own right, and the MUST NOT against interleaving two messages with its extension escape

## Configuration

```toml
[violations.websocket_frame_control_fragmentation_forbidden]
# A control frame is fragmented
severity = "warn"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
