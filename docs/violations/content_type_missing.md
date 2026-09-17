<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_type_missing

A message carries content and does not say what it is

## Message

Response contains content but no Content-Type header

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type — the SHOULD, the exception that excuses a sender who does not know the type, the recipient's two fallbacks, and what sniffing costs

## Configuration

```toml
[violations.content_type_missing]
# A message carries content and does not say what it is
severity = "warn"
```

## Reported By

- [content_type_present](../rules/content_type_present.md)
