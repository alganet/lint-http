<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# vary_prefer_missing

A response applied a preference its Vary does not nominate

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): The `Vary` MUST for a server that applies a preference which might vary a cache's handling of the response entity, and the `Vary: *` alternative it offers instead

## Configuration

```toml
[violations.vary_prefer_missing]
# A response applied a preference its Vary does not nominate
severity = "warn"
```

## Reported By

- [prefer_header_and_preference_applied](../rules/prefer_header_and_preference_applied.md)
