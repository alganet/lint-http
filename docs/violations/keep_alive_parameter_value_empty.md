<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# keep_alive_parameter_value_empty

Keep-Alive writes a parameter '=' with no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 2068 §3.7](https://www.rfc-editor.org/rfc/rfc2068.html#section-3.7): `value = token | quoted-string`, the right-hand half of `keepalive-param`. The rule name is defined once for the document and `keepalive-param` uses it, which is why a parameter value may be quoted at all

## Configuration

```toml
[violations.keep_alive_parameter_value_empty]
# Keep-Alive writes a parameter '=' with no value after it
severity = "warn"
```

## Reported By

- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
