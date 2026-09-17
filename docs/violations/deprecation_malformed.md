<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# deprecation_malformed

A Deprecation is not a Structured Field Date

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9745 §2.1](https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1): Syntax: `Deprecation` is an Item Structured Header Field whose value MUST be a `Date`

## Configuration

```toml
[violations.deprecation_malformed]
# A Deprecation is not a Structured Field Date
severity = "warn"
```

## Reported By

- [deprecation_header_syntax](../rules/deprecation_header_syntax.md)
