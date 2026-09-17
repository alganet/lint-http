<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_encoding_chunked_position_invalid

The chunked transfer coding is not the final one

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — every requirement this rule enforces is here: chunked at most once, and chunked last (unconditionally for requests, or the connection closes for responses)

## Configuration

```toml
[violations.transfer_encoding_chunked_position_invalid]
# The chunked transfer coding is not the final one
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [transfer_encoding_chunked_final](../rules/transfer_encoding_chunked_final.md)
