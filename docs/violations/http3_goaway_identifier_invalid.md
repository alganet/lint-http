<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http3_goaway_identifier_invalid

A GOAWAY identifier is larger than one already sent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9114 §5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2): Connection Shutdown — the GOAWAY identifier and whose id space it is drawn from, the connection error a larger one draws, and the prohibition on starting anything new past it

## Configuration

```toml
[violations.http3_goaway_identifier_invalid]
# A GOAWAY identifier is larger than one already sent
severity = "error"
```

## Reported By

- [http3_goaway_semantics](../rules/http3_goaway_semantics.md)
