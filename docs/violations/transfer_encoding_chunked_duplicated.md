<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_encoding_chunked_duplicated

The chunked transfer coding is applied more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — every requirement this rule enforces is here: chunked at most once, and chunked last (unconditionally for requests, or the connection closes for responses)

## Configuration

```toml
[violations.transfer_encoding_chunked_duplicated]
# The chunked transfer coding is applied more than once
severity = "warn"
```

## Reported By

- [transfer_encoding_chunked_final](../rules/transfer_encoding_chunked_final.md)
