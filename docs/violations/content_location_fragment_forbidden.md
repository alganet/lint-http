<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_location_fragment_forbidden

Content-Location carries a fragment component

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References — `partial-URI` is the rule for protocol elements carrying a relative URI but no fragment, and an element's own ABNF says which forms of reference it allows

## Configuration

```toml
[violations.content_location_fragment_forbidden]
# Content-Location carries a fragment component
severity = "warn"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
