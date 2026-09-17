<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_coding_wildcard_forbidden

The Accept-Encoding wildcard is written where a coding belongs

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): The wider Accept-Encoding grammar (`codings = content-coding / "identity" / "*"`), which is why the two headers are checked against different vocabularies

## Configuration

```toml
[violations.content_coding_wildcard_forbidden]
# The Accept-Encoding wildcard is written where a coding belongs
severity = "warn"
```

## Reported By

- [content_encoding_and_type_consistent](../rules/content_encoding_and_type_consistent.md)
- [content_encoding_registered](../rules/content_encoding_registered.md)
