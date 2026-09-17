<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# prefer_preference_invalid

A defined preference carries a value its production does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7240 §4](https://www.rfc-editor.org/rfc/rfc7240.html#section-4): The four preferences this document defines, each with its own production: `respond-async` (§4.1), `return` (§4.2), `wait` (§4.3) and `handling` (§4.4). §4.2 and §4.4 add that the two values of `return` and of `handling` are mutually exclusive

## Configuration

```toml
[violations.prefer_preference_invalid]
# A defined preference carries a value its production does not admit
severity = "warn"
```

## Reported By

- [prefer_header_valid](../rules/prefer_header_valid.md)
