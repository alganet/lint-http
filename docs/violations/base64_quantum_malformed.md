<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# base64_quantum_malformed

Value is not a whole number of base64 groups

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4): Base 64 Encoding — the 24-bit group written as four characters, and the padding that completes a final group of fewer bits

## Configuration

```toml
[violations.base64_quantum_malformed]
# Value is not a whole number of base64 groups
severity = "error"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
