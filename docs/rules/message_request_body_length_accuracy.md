<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Request Body Length Accuracy

## Description

When a request includes a `Content-Length` header, its numeric value MUST match the actual length in bytes of the captured request body after HTTP framing has been resolved (for example, after processing chunked transfer-coding), but not necessarily after any `Content-Encoding` (such as gzip) has been decoded. Mismatches indicate truncated or malformed requests and can lead to framing errors or request smuggling vulnerabilities. This rule validates that `Content-Length` (when present and syntactically valid) equals the captured body length recorded in the transaction.

## Specifications

- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length header field usage.
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length determination and framing (how body length is determined and handled).

## Configuration

```toml
[rules.message_request_body_length_accuracy]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
POST /upload HTTP/1.1
Content-Length: 3

abc
```

### ❌ Bad (mismatched Content-Length)

```http
POST /upload HTTP/1.1
Content-Length: 10

abc
```

### ❌ Bad (invalid Content-Length)

```http
POST /upload HTTP/1.1
Content-Length: abc

abc
```
