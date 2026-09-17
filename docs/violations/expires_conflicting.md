<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# expires_conflicting

Expires and the Cache-Control freshness directives disagree

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3): `Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date ("0" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control

## Configuration

```toml
[violations.expires_conflicting]
# Expires and the Cache-Control freshness directives disagree
severity = "warn"
```

## Reported By

- [expires_and_cache_control_consistent](../rules/expires_and_cache_control_consistent.md)
