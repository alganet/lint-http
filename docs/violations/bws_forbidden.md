<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# bws_forbidden

Whitespace written where the grammar admits BWS

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — `BWS` is printed where a grammar allows optional whitespace for historical reasons only, with a MUST NOT on the sender and a matching MUST on the recipient to remove it before interpreting the element

## Configuration

```toml
[violations.bws_forbidden]
# Whitespace written where the grammar admits BWS
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
- [prefer_header_valid](../rules/prefer_header_valid.md)
- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
- [te_header_valid](../rules/te_header_valid.md)
