<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# date_missing

A response does not say when it was written

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1): `Date` — when the message was originated, who must generate it, who must not, and what a recipient does when it is absent

## Configuration

```toml
[violations.date_missing]
# A response does not say when it was written
severity = "warn"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
