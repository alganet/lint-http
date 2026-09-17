<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# expect_value_empty

Expect writes an expectation '=' with no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1): Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure

## Configuration

```toml
[violations.expect_value_empty]
# Expect writes an expectation '=' with no value after it
severity = "warn"
```

## Reported By

- [expect_header_valid](../rules/expect_header_valid.md)
