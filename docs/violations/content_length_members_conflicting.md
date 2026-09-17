<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_members_conflicting

Content-Length is declared twice with different numbers

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
