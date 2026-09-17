<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_immutable_ignored

A still-fresh immutable response is revalidated anyway

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 8246 §2](https://www.rfc-editor.org/rfc/rfc8246.html#section-2): `immutable` — clients SHOULD NOT revalidate during the response's freshness lifetime, and the extension applies during that lifetime only, so a response with none is outside it entirely

## Configuration

```toml
[violations.cache_control_immutable_ignored]
# A still-fresh immutable response is revalidated anyway
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [immutable_cache_never_stale](../rules/immutable_cache_never_stale.md)
