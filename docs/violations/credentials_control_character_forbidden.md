<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# credentials_control_character_forbidden

Credentials hold a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`

## Configuration

```toml
[violations.credentials_control_character_forbidden]
# Credentials hold a control character
severity = "error"
```

## Reported By

- [authorization_credentials_valid](../rules/authorization_credentials_valid.md)
