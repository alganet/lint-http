<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# pragma_conflicting

A request asks for no-cache in the field its Cache-Control overrides

## Message

Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all

## Configuration

```toml
[violations.pragma_conflicting]
# A request asks for no-cache in the field its Cache-Control overrides
severity = "warn"
```

## Reported By

- [cache_control_and_pragma_consistent](../rules/cache_control_and_pragma_consistent.md)
