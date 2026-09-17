<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_302_ambiguous

A 302 answers a POST, leaving the redirected method undetermined

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3): 302 Found: the same permission, answered by 307 rather than by 308 — the alternative is per status

## Configuration

```toml
[violations.status_302_ambiguous]
# A 302 answers a POST, leaving the redirected method undetermined
severity = "warn"
```

## Reported By

- [status_3xx_vs_request_method](../rules/status_3xx_vs_request_method.md)
