<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_positions_conflicting

Content-Range first-pos is greater than its last-pos

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4): Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges

## Configuration

```toml
[violations.content_range_positions_conflicting]
# Content-Range first-pos is greater than its last-pos
severity = "error"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
