<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_invalid

The status code is outside the range 100..599

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): Status Codes: the three-digit code, the 100..599 range, the statement that values outside it are invalid, what 600..999 is used for, what a client does with an invalid code, and that a request's interim responses are followed by exactly one final response

## Configuration

```toml
[violations.status_invalid]
# The status code is outside the range 100..599
severity = "warn"
```

## Reported By

- [status_code_valid_range](../rules/status_code_valid_range.md)
