<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_101_unsolicited

101 Switching Protocols is sent on a version with no upgrade mechanism

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the mechanism a 101 answers, the MUST NOT on switching to a protocol the client did not indicate, and the MUST that a server ignore an `Upgrade` received in an HTTP/1.0 request
- [RFC 9113 §8.6](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6): The Upgrade Header Field — HTTP/2 does not support the 101 status code, and says why: its semantics are not applicable to a multiplexed protocol
- [RFC 9114 §4.5](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5): HTTP Upgrade — the only place RFC 9114 mentions 101, withholding the upgrade mechanism and the status code together

## Configuration

```toml
[violations.status_101_unsolicited]
# 101 Switching Protocols is sent on a version with no upgrade mechanism
severity = "warn"
```

## Reported By

- [status_101_switching_protocols](../rules/status_101_switching_protocols.md)
