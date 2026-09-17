<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_empty

A precondition is written with no validator in it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.conditional_empty]
# A precondition is written with no validator in it
severity = "warn"
```

## Reported By

- [conditional_etag_syntax](../rules/conditional_etag_syntax.md)
