<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# problem_details_missing

An error response carries a generic media type and no error format

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9457 §1](https://www.rfc-editor.org/rfc/rfc9457.html#section-1): Which status codes problem details suit, and the two sentences saying an application-specific format is often the better answer — between them the reason this finding is advice and not a defect

## Configuration

```toml
[violations.problem_details_missing]
# An error response carries a generic media type and no error format
severity = "info"
```

## Reported By

- [problem_details_content_type](../rules/problem_details_content_type.md)
