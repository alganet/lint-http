<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# proxy_authenticate_redundant

Proxy-Authenticate arrives on a status that gives it nothing to do

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1): `Proxy-Authenticate` — at least one field in each 407 a proxy generates, and the sentence limiting the field to the next outbound client on the response chain, which is all that stands behind an advisory finding on any other status

## Configuration

```toml
[violations.proxy_authenticate_redundant]
# Proxy-Authenticate arrives on a status that gives it nothing to do
severity = "info"
```

## Reported By

- [status_code_semantics](../rules/status_code_semantics.md)
