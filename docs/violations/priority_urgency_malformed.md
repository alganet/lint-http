<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# priority_urgency_malformed

Priority urgency is not an Integer

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9218 §4.1](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1): Urgency — an Integer between 0 and 7 inclusive, in descending order of priority, defaulting to 3

## Configuration

```toml
[violations.priority_urgency_malformed]
# Priority urgency is not an Integer
severity = "warn"
```

## Reported By

- [priority_header_syntax](../rules/priority_header_syntax.md)
