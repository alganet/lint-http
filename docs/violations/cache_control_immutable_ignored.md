<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_immutable_ignored

A still-fresh immutable response is revalidated anyway

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 8246 §2](https://www.rfc-editor.org/rfc/rfc8246.html#section-2): `immutable` — clients SHOULD NOT revalidate during the response's freshness lifetime, and the extension applies during that lifetime only, so a response with none is outside it entirely

## Configuration

```toml
[violations.cache_control_immutable_ignored]
# A still-fresh immutable response is revalidated anyway
severity = "info"
```

## Reported By

- [immutable_cache_never_stale](../rules/immutable_cache_never_stale.md)
