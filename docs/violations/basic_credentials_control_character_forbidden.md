<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# basic_credentials_control_character_forbidden

Basic credentials hold a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7617 §2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2): The 'Basic' Authentication Scheme — `user-pass = userid ":" password`, base64-encoded, with control characters forbidden in either half

## Configuration

```toml
[violations.basic_credentials_control_character_forbidden]
# Basic credentials hold a control character
severity = "error"
```

## Reported By

- [basic_auth_base64_valid](../rules/basic_auth_base64_valid.md)
