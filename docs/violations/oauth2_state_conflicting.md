<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# oauth2_state_conflicting

A callback's state matches no request that was seen

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6749 §4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1): Authorization Request — response_type MUST be "code"; the state parameter is RECOMMENDED

## Configuration

```toml
[violations.oauth2_state_conflicting]
# A callback's state matches no request that was seen
severity = "warn"
```

## Reported By

- [oauth2_code_flow](../rules/oauth2_code_flow.md)
