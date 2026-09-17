<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_validator_missing

A precondition names a validator this exchange never provided

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.conditional_validator_missing]
# A precondition names a validator this exchange never provided
severity = "info"
```

## Reported By

- [conditional_request_handling](../rules/conditional_request_handling.md)
