<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sunset_conflicting

A Sunset names a time before the Deprecation beside it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9745 §4](https://www.rfc-editor.org/rfc/rfc9745.html#section-4): The `Sunset` timestamp MUST NOT be earlier than the `Deprecation` one

## Configuration

```toml
[violations.sunset_conflicting]
# A Sunset names a time before the Deprecation beside it
severity = "warn"
```

## Reported By

- [sunset_and_deprecation_consistent](../rules/sunset_and_deprecation_consistent.md)
