<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_extensions_parameter_value_empty

Sec-WebSocket-Extensions writes a parameter '=' with no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 6455 §9.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1): Negotiating Extensions — the grammar, the MUST that makes a non-conforming value a failure of the connection, the note that the notation is RFC 2616's, and the requirement on a quoted-string value after unescaping

## Configuration

```toml
[violations.sec_websocket_extensions_parameter_value_empty]
# Sec-WebSocket-Extensions writes a parameter '=' with no value after it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [sec_websocket_extensions_syntax](../rules/sec_websocket_extensions_syntax.md)
