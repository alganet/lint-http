<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_wildcard_forbidden

A media range is written where one media type belongs

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept and its `media-range` — where the asterisk groups media types into ranges, which is the reason it names nothing in a Content-Type

## Configuration

```toml
[violations.media_type_wildcard_forbidden]
# A media range is written where one media type belongs
severity = "warn"
```

## Reported By

- [content_type_valid](../rules/content_type_valid.md)
