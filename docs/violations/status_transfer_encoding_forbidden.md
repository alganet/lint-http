<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_transfer_encoding_forbidden

A 1xx or 204 carries a Transfer-Encoding field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — a MUST NOT on 1xx and 204, and a MAY on a 304 to a GET. HTTP/1.1's document, so the check does not run on later versions

## Configuration

```toml
[violations.status_transfer_encoding_forbidden]
# A 1xx or 204 carries a Transfer-Encoding field
severity = "error"
```

## Reported By

- [no_body_for_1xx_204_304](../rules/no_body_for_1xx_204_304.md)
