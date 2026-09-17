<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_case_invalid

A method is a standardized name written in another case

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): `method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method

## Configuration

```toml
[violations.method_case_invalid]
# A method is a standardized name written in another case
severity = "warn"
```

## Reported By

- [request_method_token_valid](../rules/request_method_token_valid.md)
