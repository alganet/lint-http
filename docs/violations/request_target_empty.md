<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_empty

A request-line carries no request-target

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Conformance — a sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules

## Configuration

```toml
[violations.request_target_empty]
# A request-line carries no request-target
severity = "error"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
