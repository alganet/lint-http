<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_malformed

Structured field value derives from no structured type

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9651 §4.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2): Parsing — the algorithm a recipient runs over a joined field value, the `field_type` it is given, the ASCII conversion it does before choosing one, and the two answers it offers when parsing fails

## Configuration

```toml
[violations.structured_field_malformed]
# Structured field value derives from no structured type
severity = "warn"
```

## Reported By

- [structured_headers_valid](../rules/structured_headers_valid.md)
