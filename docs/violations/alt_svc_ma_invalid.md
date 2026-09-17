<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_ma_invalid

Alt-Svc states a freshness lifetime that cannot be what was meant

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.alt_svc_ma_invalid]
# Alt-Svc states a freshness lifetime that cannot be what was meant
severity = "warn"
```

## Reported By

- [alt_svc_h3_advertisement_valid](../rules/alt_svc_h3_advertisement_valid.md)
