<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# range_spec_malformed

A bytes range specifier derives from neither of the unit's two forms

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §14.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2): Byte Ranges: the two forms the `bytes` unit defines, both `1*DIGIT`, with `other-range` withdrawn for this unit. It also requires recipients to anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows — so positions are compared as digits and no ceiling is imposed — and it defines satisfiability, which is a question about the representation and not about the field

## Configuration

```toml
[violations.range_spec_malformed]
# A bytes range specifier derives from neither of the unit's two forms
severity = "warn"
```

## Reported By

- [range_header_syntax](../rules/range_header_syntax.md)
