<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_fetch_dest_value_invalid

Sec-Fetch-Dest names no request destination Fetch defines

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch Metadata §2.1](https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest-header): Fetch Metadata (W3C) — `Sec-Fetch-Dest`: an sf-token whose valid values are Fetch's request destinations

## Configuration

```toml
[violations.sec_fetch_dest_value_invalid]
# Sec-Fetch-Dest names no request destination Fetch defines
severity = "warn"
```

## Reported By

- [sec_fetch_dest_value_valid](../rules/sec_fetch_dest_value_valid.md)
