<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_value_conflicting

A cookie carries a value the observed exchange did not set

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.cookie_value_conflicting]
# A cookie carries a value the observed exchange did not set
severity = "info"
```

## Reported By

- [cookie_lifecycle](../rules/cookie_lifecycle.md)
