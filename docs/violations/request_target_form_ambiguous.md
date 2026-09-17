<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_form_ambiguous

A request-target derives from two of the four forms at once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.request_target_form_ambiguous]
# A request-target derives from two of the four forms at once
severity = "warn"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
