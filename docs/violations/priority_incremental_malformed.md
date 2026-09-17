<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# priority_incremental_malformed

Priority incremental is not a Boolean

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9218 §4.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.2): Incremental — a Boolean saying whether the response can be processed as it arrives, defaulting to false

## Configuration

```toml
[violations.priority_incremental_malformed]
# Priority incremental is not a Boolean
severity = "warn"
```

## Reported By

- [priority_header_syntax](../rules/priority_header_syntax.md)
