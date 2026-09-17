<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_date_redundant

A date conditional is sent beside the entity-tag conditional that supersedes it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, MUST ignore it when the value is no HTTP-date or has more than one member or the method is neither GET nor HEAD, and SHOULD answer a false condition with a 304 rather than performing the method
- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): `If-Unmodified-Since`: the recipient MUST ignore it when an `If-Match` is present, and when the value is no HTTP-date

## Configuration

```toml
[violations.conditional_date_redundant]
# A date conditional is sent beside the entity-tag conditional that supersedes it
severity = "info"
```

## Reported By

- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
