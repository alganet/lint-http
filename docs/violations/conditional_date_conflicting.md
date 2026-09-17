<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_date_conflicting

A date precondition names a time after the request's own Date

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.conditional_date_conflicting]
# A date precondition names a time after the request's own Date
severity = "info"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
