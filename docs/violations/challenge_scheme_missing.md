<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# challenge_scheme_missing

Authentication parameter arrives before any scheme

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`

## Configuration

```toml
[violations.challenge_scheme_missing]
# Authentication parameter arrives before any scheme
severity = "warn"
```

## Reported By

- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
