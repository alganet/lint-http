<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_fetch_mode_value_invalid

Sec-Fetch-Mode names no request mode the document defines

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch Metadata §2.2](https://www.w3.org/TR/fetch-metadata/#sec-fetch-mode-header): Fetch Metadata (W3C) — `Sec-Fetch-Mode`: an sf-token whose valid values are the five request modes

## Configuration

```toml
[violations.sec_fetch_mode_value_invalid]
# Sec-Fetch-Mode names no request mode the document defines
severity = "warn"
```

## Reported By

- [sec_fetch_mode_value_valid](../rules/sec_fetch_mode_value_valid.md)
