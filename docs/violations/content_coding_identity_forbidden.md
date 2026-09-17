<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_coding_identity_forbidden

The identity coding is named where a coding belongs

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): `Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here

## Configuration

```toml
[violations.content_coding_identity_forbidden]
# The identity coding is named where a coding belongs
severity = "warn"
```

## Reported By

- [content_encoding_registered](../rules/content_encoding_registered.md)
