<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_no_store_ignored

A validator from a no-store response comes back on a later request

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5): `no-store` — a cache MUST NOT store any part of the request or the response, and MUST NOT use the response to satisfy another request

## Configuration

```toml
[violations.cache_control_no_store_ignored]
# A validator from a no-store response comes back on a later request
severity = "warn"
```

## Reported By

- [no_store_enforced](../rules/no_store_enforced.md)
