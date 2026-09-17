<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# priority_incremental_malformed

Priority incremental is not a Boolean

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9218 §4.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.2): Incremental — a Boolean saying whether the response can be processed as it arrives, defaulting to false

## Configuration

```toml
[violations.priority_incremental_malformed]
# Priority incremental is not a Boolean
severity = "warn"
```

## Reported By

- [priority_header_syntax](../rules/priority_header_syntax.md)
