<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# priority_urgency_invalid

Priority urgency is outside 0 to 7

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9218 §4.1](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1): Urgency — an Integer between 0 and 7 inclusive, in descending order of priority, defaulting to 3

## Configuration

```toml
[violations.priority_urgency_invalid]
# Priority urgency is outside 0 to 7
severity = "warn"
```

## Reported By

- [priority_header_syntax](../rules/priority_header_syntax.md)
