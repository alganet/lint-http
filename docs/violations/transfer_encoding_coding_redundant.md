<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_encoding_coding_redundant

A coding is applied in transit that the representation already carries

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §7.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.3): Transfer and content coding names may only overlap where the transformation is identical — so a shared name is unambiguous, and coding twice is coherent rather than malformed

## Configuration

```toml
[violations.transfer_encoding_coding_redundant]
# A coding is applied in transit that the representation already carries
severity = "info"
```

## Reported By

- [compression_and_transfer_encoding_consistent](../rules/compression_and_transfer_encoding_consistent.md)
