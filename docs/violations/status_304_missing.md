<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_304_missing

A false precondition is answered with 200 rather than 304

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): `If-None-Match`: an origin server MUST NOT perform the method when the condition is false and MUST answer with a 304 for GET or HEAD, or a 412 otherwise
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, MUST ignore it when the value is no HTTP-date or has more than one member or the method is neither GET nor HEAD, and SHOULD answer a false condition with a 304 rather than performing the method

## Configuration

```toml
[violations.status_304_missing]
# A false precondition is answered with 200 rather than 304
severity = "warn"
```

## Reported By

- [conditional_request_handling](../rules/conditional_request_handling.md)
