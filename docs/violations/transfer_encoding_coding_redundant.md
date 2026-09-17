<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_encoding_coding_redundant

A coding is applied in transit that the representation already carries

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

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
