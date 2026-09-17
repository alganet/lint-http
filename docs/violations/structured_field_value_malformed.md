<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_value_malformed

Structured field value is none of the bare item types

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them

## Configuration

```toml
[violations.structured_field_value_malformed]
# Structured field value is none of the bare item types
severity = "warn"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
- [priority_header_syntax](../rules/priority_header_syntax.md)
