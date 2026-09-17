<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# trailer_field_forbidden

A trailer field's definition does not permit the usage

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): Limitations on use of trailers — a trailer field is permitted only where the field's own definition says so, which is deny-by-default and therefore reportable only for the definitions a linter holds

## Configuration

```toml
[violations.trailer_field_forbidden]
# A trailer field's definition does not permit the usage
severity = "warn"
```

## Reported By

- [trailer_fields_valid](../rules/trailer_fields_valid.md)
