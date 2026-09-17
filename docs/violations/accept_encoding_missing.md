<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_encoding_missing

Request expresses no content-coding preference

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): `Accept-Encoding`: `#( codings [ weight ] )`, and the two sentences that make absence the most permissive value the field has and an empty value the most restrictive

## Configuration

```toml
[violations.accept_encoding_missing]
# Request expresses no content-coding preference
severity = "info"
```

## Reported By

- [accept_encoding_present](../rules/accept_encoding_present.md)
