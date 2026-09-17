<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_mask_forbidden

A server frame is masked

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6455 §5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1): Overview — both masking MUSTs, the reason the client's exists, and the two recipient MUSTs that say what a conforming peer does about a breach

## Configuration

```toml
[violations.websocket_frame_mask_forbidden]
# A server frame is masked
severity = "error"
```

## Reported By

- [websocket_frame_masking](../rules/websocket_frame_masking.md)
