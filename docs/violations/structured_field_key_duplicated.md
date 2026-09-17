<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_key_duplicated

Structured field gives one Dictionary key more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it

## Configuration

```toml
[violations.structured_field_key_duplicated]
# Structured field gives one Dictionary key more than once
severity = "warn"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
- [priority_header_syntax](../rules/priority_header_syntax.md)
