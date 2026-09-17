<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# referer_empty

A Referer is written with nothing in it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §10.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3): Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals

## Configuration

```toml
[violations.referer_empty]
# A Referer is written with nothing in it
severity = "info"
```

## Reported By

- [referer_uri_valid](../rules/referer_uri_valid.md)
