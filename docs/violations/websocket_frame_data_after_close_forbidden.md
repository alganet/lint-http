<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_data_after_close_forbidden

A data frame follows the same endpoint's Close frame

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6455 §5.5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1): Close — the body is optional, a body that exists opens with a two-byte status code, and a sender's own Close ends what it may send

## Configuration

```toml
[violations.websocket_frame_data_after_close_forbidden]
# A data frame follows the same endpoint's Close frame
severity = "warn"
```

## Reported By

- [websocket_frame_opcode_sequence](../rules/websocket_frame_opcode_sequence.md)
