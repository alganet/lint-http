<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_content_length_forbidden

A 1xx or 204 carries a Content-Length field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length — a MUST NOT on 1xx and 204 at any value, and a MAY on a 304 to a conditional GET. That MAY's own MUST NOT (the value must equal the unsent 200's content length) is undecidable from one exchange and is left unenforced

## Configuration

```toml
[violations.status_content_length_forbidden]
# A 1xx or 204 carries a Content-Length field
severity = "error"
```

## Reported By

- [no_body_for_1xx_204_304](../rules/no_body_for_1xx_204_304.md)
