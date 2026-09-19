<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# ext_value_charset_forbidden

An extended parameter value names a character encoding reserved for future use

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 8187 §3.2.1](https://www.rfc-editor.org/rfc/rfc8187.html#section-3.2.1): `ext-value = charset "'" [ language ] "'" value-chars` — the charset that may not be empty, the language that may be, and the `value-chars` made of `pct-encoded` and `attr-char`. Obsoletes RFC 5987, which older references named; the production is unchanged

## Configuration

```toml
[violations.ext_value_charset_forbidden]
# An extended parameter value names a character encoding reserved for future use
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
- [link_header_valid](../rules/link_header_valid.md)
