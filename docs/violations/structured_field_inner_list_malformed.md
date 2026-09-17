<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_inner_list_malformed

Structured field Inner List has no closing parenthesis

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9651 §4.2.1.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.1.2): Parsing an Inner List — space-separated Items between a `(` and a `)`, and the failure when the closing parenthesis never arrives

## Configuration

```toml
[violations.structured_field_inner_list_malformed]
# Structured field Inner List has no closing parenthesis
severity = "warn"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
- [priority_header_syntax](../rules/priority_header_syntax.md)
