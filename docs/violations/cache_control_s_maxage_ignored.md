<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_s_maxage_ignored

A cache s-maxage does not address used it for freshness

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10): `s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache

## Configuration

```toml
[violations.cache_control_s_maxage_ignored]
# A cache s-maxage does not address used it for freshness
severity = "warn"
```

## Reported By

- [s_max_age_enforced](../rules/s_max_age_enforced.md)
