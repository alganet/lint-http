<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_405_allow_conflicting

A 405 advertises the method it refuses

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.5.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.6): The status code and its MUST — including the clause after "containing", which asks the field to hold the methods the target resource supports and so contradicts a list naming the method this response refuses

## Configuration

```toml
[violations.status_405_allow_conflicting]
# A 405 advertises the method it refuses
severity = "warn"
```

## Reported By

- [status_405_allow_valid](../rules/status_405_allow_valid.md)
