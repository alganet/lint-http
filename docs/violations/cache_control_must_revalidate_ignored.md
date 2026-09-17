<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_must_revalidate_ignored

A stale must-revalidate response is reused without validation

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9111 §5.2.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2): `must-revalidate` — once the response is stale, a cache MUST NOT reuse it until it has been successfully validated by the origin

## Configuration

```toml
[violations.cache_control_must_revalidate_ignored]
# A stale must-revalidate response is reused without validation
severity = "warn"
```

## Reported By

- [must_revalidate_enforced](../rules/must_revalidate_enforced.md)
