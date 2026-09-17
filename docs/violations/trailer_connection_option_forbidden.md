<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# trailer_connection_option_forbidden

A trailer field is named as a connection-option in this message

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): `Connection` — naming a field as a connection-option declares it hop-by-hop, and every intermediary removes it from the header *and trailer* sections before forwarding

## Configuration

```toml
[violations.trailer_connection_option_forbidden]
# A trailer field is named as a connection-option in this message
severity = "warn"
```

## Reported By

- [trailer_fields_valid](../rules/trailer_fields_valid.md)
