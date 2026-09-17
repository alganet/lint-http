<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_empty

Content-Length declares no length

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against

## Configuration

```toml
[violations.content_length_empty]
# Content-Length declares no length
severity = "error"
```

## Reported By

- [content_length_valid](../rules/content_length_valid.md)
