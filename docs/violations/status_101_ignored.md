<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_101_ignored

HTTP continues on a connection a 101 handed off

## Message

HTTP traffic after 101 Switching Protocols on the same connection; the connection should have been handed off to the upgraded protocol

## Specifications

- [RFC 9110 §15.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2): 101 Switching Protocols — the status code is a change in the application protocol being used on this connection, and the response MUST generate an `Upgrade` field naming the protocol(s) in effect after it

## Configuration

```toml
[violations.status_101_ignored]
# HTTP continues on a connection a 101 handed off
severity = "warn"
```

## Reported By

- [status_101_switching_protocols](../rules/status_101_switching_protocols.md)
