<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sunset_invalid

A Sunset names a time that has already passed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

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
