<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sunset_invalid

A Sunset names a time that has already passed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): The `Sunset` HTTP header field — an `HTTP-date` timestamp that SHOULD be in the future

## Configuration

```toml
[violations.sunset_invalid]
# A Sunset names a time that has already passed
severity = "warn"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
