<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_coding_parameter_missing

A coding writes a ';' with no parameter after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender and `t-codings` is written out — the alternation that gives the `trailers` keyword neither a parameter nor a weight

## Configuration

```toml
[violations.transfer_coding_parameter_missing]
# A coding writes a ';' with no parameter after it
severity = "warn"
```

## Reported By

- [te_header_valid](../rules/te_header_valid.md)
