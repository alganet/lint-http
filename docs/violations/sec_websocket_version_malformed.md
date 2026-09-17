<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_version_malformed

Sec-WebSocket-Version derives from no version production

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 6455 §4.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3): Collected ABNF — `version = DIGIT | (NZDIGIT DIGIT) | ("1" DIGIT DIGIT) | ("2" DIGIT DIGIT)` with the comment limiting it to 0-255 and no leading zeros, the `-Client`/`-Server` suffixes that make a request's field one version and a response's a list of them, and the handshake's other fields collected beside it: `Sec-WebSocket-Key = base64-value-non-empty` and `Sec-WebSocket-Protocol-Client = 1#token`

## Configuration

```toml
[violations.sec_websocket_version_malformed]
# Sec-WebSocket-Version derives from no version production
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
- [sec_websocket_version_advertised](../rules/sec_websocket_version_advertised.md)
