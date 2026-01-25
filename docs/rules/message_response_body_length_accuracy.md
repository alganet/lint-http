<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Response Body Length Accuracy

## Description

When a response includes a `Content-Length` header, its numeric value MUST match the actual length in bytes of the captured response body after HTTP framing has been resolved (for example, after processing chunked transfer-coding), but not necessarily after any `Content-Encoding` (such as gzip) has been decoded. Mismatches indicate truncated or malformed responses and can lead to framing errors, truncated reads, or incorrect downstream handling. This rule validates that `Content-Length` (when present and syntactically valid) equals the captured body length recorded in the transaction.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): The `Content-Length` header field and rules about forwarding incorrect values.
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length determination and framing (how body length is determined and handled).

## Configuration

```toml
[rules.message_response_body_length_accuracy]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Length: 3

abc
```

### ❌ Bad (mismatched Content-Length)

```http
HTTP/1.1 200 OK
Content-Length: 10

abc
```

### ❌ Bad (invalid Content-Length)

```http
HTTP/1.1 200 OK
Content-Length: abc

abc
```

