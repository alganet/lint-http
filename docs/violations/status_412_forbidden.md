<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_412_forbidden

A GET or HEAD whose If-None-Match was false is answered 412 rather than 304

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): `If-None-Match`: an origin server MUST NOT perform the method when the condition is false and MUST answer with a 304 for GET or HEAD, or a 412 otherwise

## Configuration

```toml
[violations.status_412_forbidden]
# A GET or HEAD whose If-None-Match was false is answered 412 rather than 304
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [conditional_request_handling](../rules/conditional_request_handling.md)
