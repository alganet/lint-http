<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_value_empty

Digest field member carries no digest

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.digest_value_empty]
# Digest field member carries no digest
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
