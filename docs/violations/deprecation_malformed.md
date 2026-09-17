<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# deprecation_malformed

A Deprecation is not a Structured Field Date

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9745 §2.1](https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1): Syntax: `Deprecation` is an Item Structured Header Field whose value MUST be a `Date`

## Configuration

```toml
[violations.deprecation_malformed]
# A Deprecation is not a Structured Field Date
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [deprecation_header_syntax](../rules/deprecation_header_syntax.md)
