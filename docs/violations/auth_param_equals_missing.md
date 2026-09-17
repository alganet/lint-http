<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# auth_param_equals_missing

An authentication parameter is written without its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet

## Configuration

```toml
[violations.auth_param_equals_missing]
# An authentication parameter is written without its '='
severity = "warn"
```

## Reported By

- [digest_auth_valid](../rules/digest_auth_valid.md)
