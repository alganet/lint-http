<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# host_userinfo_forbidden

A Host field value carries the userinfo subcomponent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — a `Host` in every HTTP/1.1 request, a value identical to the target URI's authority *excluding* the userinfo and its `@`, an empty value where the target has no authority, and the 400 a server owes a request with none or with two

## Configuration

```toml
[violations.host_userinfo_forbidden]
# A Host field value carries the userinfo subcomponent
severity = "error"
```

## Reported By

- [host_header](../rules/host_header.md)
