<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_trace_disclosure_forbidden

A TRACE request carries a field that echoes back a secret

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §9.3.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8): TRACE — the two client `MUST NOT`s, the example naming credentials and cookies, and the `SHOULD` to reflect the message, which is addressed to a recipient no message identifies

## Configuration

```toml
[violations.method_trace_disclosure_forbidden]
# A TRACE request carries a field that echoes back a secret
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [trace_method_echo](../rules/trace_method_echo.md)
