<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_opcode_malformed

The recorded opcode does not fit the four bits the header holds

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6455 §11.8](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.8): WebSocket Opcode Registry — the field's range, and the Standards Action policy that makes an unassigned value one no deployment can outrun

## Configuration

```toml
[violations.websocket_frame_opcode_malformed]
# The recorded opcode does not fit the four bits the header holds
severity = "warn"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
