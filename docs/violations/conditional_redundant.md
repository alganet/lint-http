<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_redundant

A still-fresh stored response is revalidated anyway

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.conditional_redundant]
# A still-fresh stored response is revalidated anyway
severity = "info"
```

## Reported By

- [max_age_directive_valid](../rules/max_age_directive_valid.md)
