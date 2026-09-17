<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_timing_param_name_invalid

Server-Timing names an established parameter in a case no getter matches

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.server_timing_param_name_invalid]
# Server-Timing names an established parameter in a case no getter matches
severity = "info"
```

## Reported By

- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
