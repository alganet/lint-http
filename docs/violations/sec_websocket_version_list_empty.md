<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_version_list_empty

Sec-WebSocket-Version advertises no version

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 2616 §2.1](https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1): Augmented BNF — the notation RFC 6455 imports by name (§9.1 for the extension list, §4.3 for the collected grammar): the `#rule` whose null elements are allowed (RFC 9110 §5.6.1.1 forbids them) and which requires one that is not, and the implied *LWS rule that permits whitespace beside the separators. Obsolete and correct: the current document is what sends the reader here

## Configuration

```toml
[violations.sec_websocket_version_list_empty]
# Sec-WebSocket-Version advertises no version
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [sec_websocket_version_advertised](../rules/sec_websocket_version_advertised.md)
