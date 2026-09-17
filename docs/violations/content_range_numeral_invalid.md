<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_numeral_invalid

Content-Range numeral is too large to represent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §14.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2): Byte Ranges — positions are decimal numbers of octets, and recipients must anticipate large ones rather than overflow on them

## Configuration

```toml
[violations.content_range_numeral_invalid]
# Content-Range numeral is too large to represent
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
