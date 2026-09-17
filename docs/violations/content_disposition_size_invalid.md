<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_size_invalid

A Content-Disposition size parameter is not a number

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.content_disposition_size_invalid]
# A Content-Disposition size parameter is not a number
severity = "info"
```

## Reported By

- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
