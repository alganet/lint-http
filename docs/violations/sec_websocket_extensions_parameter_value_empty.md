<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_websocket_extensions_parameter_value_empty

Sec-WebSocket-Extensions writes a parameter '=' with no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6455 §9.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1): Negotiating Extensions — the grammar, the MUST that makes a non-conforming value a failure of the connection, the note that the notation is RFC 2616's, and the requirement on a quoted-string value after unescaping

## Configuration

```toml
[violations.sec_websocket_extensions_parameter_value_empty]
# Sec-WebSocket-Extensions writes a parameter '=' with no value after it
severity = "error"
```

## Reported By

- [sec_websocket_extensions_syntax](../rules/sec_websocket_extensions_syntax.md)
