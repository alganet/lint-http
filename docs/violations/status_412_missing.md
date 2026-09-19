<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_412_missing

A false precondition on a state-changing request is answered with success rather than 412

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1): `If-Match`: an origin server MUST NOT perform the method when the condition is false, MAY answer 412, and MAY answer 2xx where the state-changing request appears to have already been applied
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): `If-None-Match`: an origin server MUST NOT perform the method when the condition is false and MUST answer with a 304 for GET or HEAD, or a 412 otherwise
- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): `If-Unmodified-Since`: the recipient MUST ignore it when an `If-Match` is present, and when the value is no HTTP-date

## Configuration

```toml
[violations.status_412_missing]
# A false precondition on a state-changing request is answered with success rather than 412
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [conditional_request_handling](../rules/conditional_request_handling.md)
