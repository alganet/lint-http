<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# via_received_by_missing

Via member names no received-by

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): The `Via` grammar — `Via = #( received-protocol RWS received-by [ RWS comment ] )` — the sentence that puts the field in both directions, and the requirements about forwarding and combining that a single captured message cannot answer

## Configuration

```toml
[violations.via_received_by_missing]
# Via member names no received-by
severity = "warn"
```

## Reported By

- [via_header_syntax](../rules/via_header_syntax.md)
