<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# keep_alive_parameter_value_empty

Keep-Alive writes a parameter '=' with no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 2068 §3.7](https://www.rfc-editor.org/rfc/rfc2068.html#section-3.7): `value = token | quoted-string`, the right-hand half of `keepalive-param`. The rule name is defined once for the document and `keepalive-param` uses it, which is why a parameter value may be quoted at all

## Configuration

```toml
[violations.keep_alive_parameter_value_empty]
# Keep-Alive writes a parameter '=' with no value after it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
