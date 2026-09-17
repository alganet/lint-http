<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_101_forbidden

A 101 completes a WebSocket handshake the server had to refuse

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 6455 §4.2.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1): Reading the Client's Opening Handshake — the description a handshake has to match, and the requirement to refuse one that does not, which is what makes a 101 over a malformed key the server's defect

## Configuration

```toml
[violations.status_101_forbidden]
# A 101 completes a WebSocket handshake the server had to refuse
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [websocket_handshake_valid](../rules/websocket_handshake_valid.md)
