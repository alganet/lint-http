<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_connection_specific_forbidden

A connection-specific field is written on a version that has none

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): Connection-Specific Header Fields — HTTP/2's prohibition, and the one sentence of the two that closes the list of names
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): HTTP Fields — HTTP/3's prohibition, which enumerates nothing and defers to RFC 9110 §7.6.1

## Configuration

```toml
[violations.field_connection_specific_forbidden]
# A connection-specific field is written on a version that has none
severity = "error"
```

## Reported By

- [no_connection_specific_fields](../rules/no_connection_specific_fields.md)
