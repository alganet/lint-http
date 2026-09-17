<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sunset_conflicting

A Sunset names a time before the Deprecation beside it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9745 §4](https://www.rfc-editor.org/rfc/rfc9745.html#section-4): The `Sunset` timestamp MUST NOT be earlier than the `Deprecation` one

## Configuration

```toml
[violations.sunset_conflicting]
# A Sunset names a time before the Deprecation beside it
severity = "warn"
```

## Reported By

- [sunset_and_deprecation_consistent](../rules/sunset_and_deprecation_consistent.md)
