<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Transfer-Encoding Chunked Final

## Description

Ensures that when `Transfer-Encoding` includes the `chunked` transfer coding, it appears as the final transfer coding.

Per RFC 9112 §7.1, the `chunked` transfer-coding must always be the final transfer-coding applied to a message. Intermediate codecs cannot follow `chunked`, because chunked encoding is the format used to delimit the message body.

If a message includes `Transfer-Encoding: ...` values and any of them is `chunked`, then `chunked` must be the final coding in the sequence. The rule checks all `Transfer-Encoding` header fields and the order of comma-separated codings.

## Specifications

- [RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1): Transfer-Encoding

## Configuration

```toml
[rules.message_transfer_encoding_chunked_final]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Transfer-Encoding: gzip, chunked

Transfer-Encoding: chunked
```

### ❌ Bad

```http
Transfer-Encoding: chunked, gzip
# chunked must be final

# Multiple header fields where an earlier field contains chunked
# and later fields contain other codings
```
