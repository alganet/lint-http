<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# last_modified_conflicting

A Last-Modified is later than the Date beside it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation — an origin server with a clock MUST NOT generate a `Last-Modified` date later than its own `Date`

## Configuration

```toml
[violations.last_modified_conflicting]
# A Last-Modified is later than the Date beside it
severity = "warn"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
