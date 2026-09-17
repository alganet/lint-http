<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_opcode_unregistered

The opcode is in a reserved range and denotes no frame type

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2): Base Framing Protocol — the opcode definitions, the two reserved ranges and what each is reserved for, and the MUST-fail a receiving endpoint owes an unknown opcode

## Configuration

```toml
[violations.websocket_frame_opcode_unregistered]
# The opcode is in a reserved range and denotes no frame type
severity = "error"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
