<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# oauth2_callback_state_missing

An authorization callback carries a code and no state

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2): Authorization Response — the callback carries the code, and echoes the exact state if the request had one

## Configuration

```toml
[violations.oauth2_callback_state_missing]
# An authorization callback carries a code and no state
severity = "warn"
```

## Reported By

- [oauth2_code_flow](../rules/oauth2_code_flow.md)
