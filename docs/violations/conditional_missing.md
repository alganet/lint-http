<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_missing

A repeat request declines a validator the server provided

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.conditional_missing]
# A repeat request declines a validator the server provided
severity = "info"
```

## Reported By

- [cached_validators_reused](../rules/cached_validators_reused.md)
