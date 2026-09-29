<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# if_range_ignored

A range is sent though the If-Range condition was false

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5): `If-Range`: `entity-tag / HTTP-date`, the first-three-characters DQUOTE test that tells them apart, the MUST NOT on a request with no `Range`, the MUST NOT on a weak entity-tag, the MUST NOT on a date where the client holds an entity tag, the strong comparison and the exact date match a recipient evaluates the condition with, and the recipient's MUST to ignore the `Range` when it is false

## Configuration

```toml
[violations.if_range_ignored]
# A range is sent though the If-Range condition was false
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
