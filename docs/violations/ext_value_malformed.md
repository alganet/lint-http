<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# ext_value_malformed

An extended parameter value is no ext-value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8187 §3.2.1](https://www.rfc-editor.org/rfc/rfc8187.html#section-3.2.1): `ext-value = charset "'" [ language ] "'" value-chars` — the charset that may not be empty, the language that may be, and the `value-chars` made of `pct-encoded` and `attr-char`. Obsoletes RFC 5987, which older references named; the production is unchanged

## Configuration

```toml
[violations.ext_value_malformed]
# An extended parameter value is no ext-value
severity = "warn"
```

## Reported By

- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
