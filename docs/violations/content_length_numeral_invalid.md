<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_numeral_invalid

Content-Length numeral is too large to represent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.content_length_numeral_invalid]
# Content-Length numeral is too large to represent
severity = "warn"
```

## Reported By

- [content_length_valid](../rules/content_length_valid.md)
