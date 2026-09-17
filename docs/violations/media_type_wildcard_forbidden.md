<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_wildcard_forbidden

A media range is written where one media type belongs

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
