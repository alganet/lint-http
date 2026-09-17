<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# prefer_preference_duplicated

A Prefer names one preference more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): `Prefer` — the grammar, the equivalence of several field lines with one, the equivalence of an empty value with no value, the case rules for names and values, the SHOULD NOT against repeating a token, and the server's MUST to ignore a preference it does not recognize

## Configuration

```toml
[violations.prefer_preference_duplicated]
# A Prefer names one preference more than once
severity = "warn"
```

## Reported By

- [prefer_header_valid](../rules/prefer_header_valid.md)
