<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# last_modified_conflicting

A Last-Modified is later than the Date beside it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation — an origin server with a clock MUST NOT generate a `Last-Modified` date later than its own `Date`

## Configuration

```toml
[violations.last_modified_conflicting]
# A Last-Modified is later than the Date beside it
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
