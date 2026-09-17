<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_missing

A 200 leaves its freshness lifetime to be guessed

## Message

Response 200 without Cache-Control header

## Specifications

- [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2): Calculating Heuristic Freshness — without an explicit expiration time a cache MAY assign one of its own, estimated from other field values

## Configuration

```toml
[violations.cache_control_missing]
# A 200 leaves its freshness lifetime to be guessed
severity = "info"
```

## Reported By

- [cache_control_present](../rules/cache_control_present.md)
