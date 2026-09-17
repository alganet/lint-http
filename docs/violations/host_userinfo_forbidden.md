<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# host_userinfo_forbidden

A Host field value carries the userinfo subcomponent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — a `Host` in every HTTP/1.1 request, a value identical to the target URI's authority *excluding* the userinfo and its `@`, an empty value where the target has no authority, and the 400 a server owes a request with none or with two

## Configuration

```toml
[violations.host_userinfo_forbidden]
# A Host field value carries the userinfo subcomponent
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [host_header](../rules/host_header.md)
