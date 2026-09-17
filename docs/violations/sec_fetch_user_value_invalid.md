<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_fetch_user_value_invalid

Sec-Fetch-User carries something other than the boolean true

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch Metadata §2.4](https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header): Fetch Metadata (W3C) — `Sec-Fetch-User`: a boolean, delivered only for navigation requests and only when its value is true

## Configuration

```toml
[violations.sec_fetch_user_value_invalid]
# Sec-Fetch-User carries something other than the boolean true
severity = "warn"
```

## Reported By

- [sec_fetch_user_value_valid](../rules/sec_fetch_user_value_valid.md)
