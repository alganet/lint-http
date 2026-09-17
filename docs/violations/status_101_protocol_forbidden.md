<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_101_protocol_forbidden

A 101 switches to a protocol the client did not indicate

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the mechanism a 101 answers, the MUST NOT on switching to a protocol the client did not indicate, and the MUST that a server ignore an `Upgrade` received in an HTTP/1.0 request

## Configuration

```toml
[violations.status_101_protocol_forbidden]
# A 101 switches to a protocol the client did not indicate
severity = "error"
```

## Reported By

- [status_101_switching_protocols](../rules/status_101_switching_protocols.md)
