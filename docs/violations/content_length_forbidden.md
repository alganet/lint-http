<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_forbidden

Content-Length is sent in a message that is transfer-coded

## Message

Both Content-Length and Transfer-Encoding present

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length as framing — the declared length is how a recipient determines where the data and the message end, and the sender-side prohibition on sending it in a message that carries a Transfer-Encoding

## Configuration

```toml
[violations.content_length_forbidden]
# Content-Length is sent in a message that is transfer-coded
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_length_vs_transfer_encoding](../rules/content_length_vs_transfer_encoding.md)
