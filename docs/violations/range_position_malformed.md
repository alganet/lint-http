<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# range_position_malformed

Range position is not 1*DIGIT

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §14.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1): Range Specifiers: `ranges-specifier = range-unit "=" range-set`, and the grammar under it is generic — each range unit says which of `int-range`, `suffix-range` and `other-range` its specifiers may use. A ranges-specifier is invalid when it holds a range-spec "that is invalid or undefined for the indicated range-unit", which is the sentence every check here rests on and the one that bounds them to the unit the rule knows

## Configuration

```toml
[violations.range_position_malformed]
# Range position is not 1*DIGIT
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_header_syntax](../rules/range_header_syntax.md)
