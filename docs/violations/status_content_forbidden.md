<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_content_forbidden

A status that cannot carry content carries some

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §6.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1): Content Semantics — the summary that names 1xx, 204 and 304 in one sentence. It is about content, not about header fields; taking it for a rule about fields is what put the 304 in front of two prohibitions that exempt it

## Configuration

```toml
[violations.status_content_forbidden]
# A status that cannot carry content carries some
severity = "error"
```

## Reported By

- [no_body_for_1xx_204_304](../rules/no_body_for_1xx_204_304.md)
