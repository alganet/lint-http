<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Accept-Encoding Present

## Description
This rule checks if the client sends an `Accept-Encoding` header in the request.

Modern HTTP clients should support compression (gzip, brotli, etc.) to reduce bandwidth usage and improve performance. Omitting this header usually implies the client does not support compression, or it was manually disabled.

## Specifications
- [RFC 7231 §5.3.4](https://www.rfc-editor.org/rfc/rfc7231.html#section-5.3.4): Accept-Encoding header

## Examples

### ✅ Good Request
```http
GET /resource HTTP/1.1
Host: example.com
Accept-Encoding: gzip, deflate, br
```

### ❌ Bad Request
```http
GET /resource HTTP/1.1
Host: example.com
User-Agent: my-script/1.0
```
