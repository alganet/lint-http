<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# websocket_frame_mask_missing

A client frame is not masked

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6455 §5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1): Overview — both masking MUSTs, the reason the client's exists, and the two recipient MUSTs that say what a conforming peer does about a breach

## Configuration

```toml
[violations.websocket_frame_mask_missing]
# A client frame is not masked
severity = "error"
```

## Reported By

- [websocket_frame_masking](../rules/websocket_frame_masking.md)
