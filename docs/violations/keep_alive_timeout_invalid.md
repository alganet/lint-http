<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# keep_alive_timeout_invalid

Keep-Alive asks for a timeout above the configured maximum

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.keep_alive_timeout_invalid]
# Keep-Alive asks for a timeout above the configured maximum
severity = "warn"
```

## Reported By

- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
