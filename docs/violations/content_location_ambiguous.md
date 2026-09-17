<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_location_ambiguous

Content-Location names a resource other than the request target

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7): Content-Location — `absolute-URI / partial-URI`, the three meanings a value differing from the target URI carries, and the sentence saying such a claim can only be trusted between identifiers with one resource owner, which HTTP cannot determine

## Configuration

```toml
[violations.content_location_ambiguous]
# Content-Location names a resource other than the request target
severity = "info"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
