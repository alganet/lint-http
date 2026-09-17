<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_417_ignored

A request repeats an expectation a 417 already refused

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1): Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure

## Configuration

```toml
[violations.status_417_ignored]
# A request repeats an expectation a 417 already refused
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [expect_header_valid](../rules/expect_header_valid.md)
