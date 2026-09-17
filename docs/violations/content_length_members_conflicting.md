<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_members_conflicting

Content-Length is declared twice with different numbers

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Why differing values are an error and why a single field line may carry a comma-separated list, provided every member is valid and identical

## Configuration

```toml
[violations.content_length_members_conflicting]
# Content-Length is declared twice with different numbers
severity = "error"
```

## Reported By

- [content_length_valid](../rules/content_length_valid.md)
