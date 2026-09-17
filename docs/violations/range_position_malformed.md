<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# range_position_malformed

Range position is not 1*DIGIT

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §14.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1): Range Specifiers: `ranges-specifier = range-unit "=" range-set`, and the grammar under it is generic — each range unit says which of `int-range`, `suffix-range` and `other-range` its specifiers may use. A ranges-specifier is invalid when it holds a range-spec "that is invalid or undefined for the indicated range-unit", which is the sentence every check here rests on and the one that bounds them to the unit the rule knows

## Configuration

```toml
[violations.range_position_malformed]
# Range position is not 1*DIGIT
severity = "warn"
```

## Reported By

- [range_header_syntax](../rules/range_header_syntax.md)
