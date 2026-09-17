<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sunset_invalid

A Sunset names a time that has already passed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): The `Sunset` HTTP header field — an `HTTP-date` timestamp that SHOULD be in the future

## Configuration

```toml
[violations.sunset_invalid]
# A Sunset names a time that has already passed
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
