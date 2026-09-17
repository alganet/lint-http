<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_validator_conflicting

A precondition names a validator older than the last one seen

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.conditional_validator_conflicting]
# A precondition names a validator older than the last one seen
severity = "info"
```

## Reported By

- [cache_validation_chain](../rules/cache_validation_chain.md)
- [range_request_and_caching](../rules/range_request_and_caching.md)
