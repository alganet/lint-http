<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_persist_invalid

Alt-Svc sets persist to a value the parameter does not define

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7838 §3.1](https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1): Caching Alt-Svc Header Field Values: the `ma` parameter's delta-seconds value states how long the alternative is considered fresh, and `persist` has exactly one defined value — `"1"` — with clients required to ignore any other

## Configuration

```toml
[violations.alt_svc_persist_invalid]
# Alt-Svc sets persist to a value the parameter does not define
severity = "info"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
