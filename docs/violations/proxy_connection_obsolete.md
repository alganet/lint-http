<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# proxy_connection_obsolete

A request carries a field the specification asks clients not to send

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9112 §C.2.2](https://www.rfc-editor.org/rfc/rfc9112.html#appendix-C.2.2): Keep-Alive Connections — the only description of the field in either core document: an attempted fix for HTTP/1.0 proxies that did not understand Connection, recorded as unworkable, with clients encouraged not to send it in any request

## Configuration

```toml
[violations.proxy_connection_obsolete]
# A request carries a field the specification asks clients not to send
severity = "info"
```

## Reported By

- [proxy_connection_discouraged](../rules/proxy_connection_discouraged.md)
