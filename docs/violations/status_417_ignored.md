<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_417_ignored

A request repeats an expectation a 417 already refused

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1): Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure

## Configuration

```toml
[violations.status_417_ignored]
# A request repeats an expectation a 417 already refused
severity = "warn"
```

## Reported By

- [expect_header_valid](../rules/expect_header_valid.md)
