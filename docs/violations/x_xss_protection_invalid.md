<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_xss_protection_invalid

X-XSS-Protection asks for something other than the filter off

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.x_xss_protection_invalid]
# X-XSS-Protection asks for something other than the filter off
severity = "info"
```

## Reported By

- [x_xss_protection_value_valid](../rules/x_xss_protection_value_valid.md)
