<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_character_forbidden

Content-Length value holds an octet DIGIT does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against

## Configuration

```toml
[violations.content_length_character_forbidden]
# Content-Length value holds an octet DIGIT does not admit
severity = "error"
```

## Reported By

- [content_length_valid](../rules/content_length_valid.md)
