<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# auth_scheme_unregistered

Authentication scheme is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1): Authentication Scheme — `auth-scheme = token`, and where new schemes are registered

## Configuration

```toml
[violations.auth_scheme_unregistered]
# Authentication scheme is not one the deployment recognises
severity = "warn"
```

## Reported By

- [auth_scheme_registered](../rules/auth_scheme_registered.md)
