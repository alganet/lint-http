<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Response 405 Allow

## Description
This rule checks if `405 Method Not Allowed` responses include an `Allow` header.

The `Allow` header is required in `405` responses to indicate the set of methods supported by the resource, so clients can discover what operations are permitted.

## Specifications
- [RFC 7231, Section 7.4.1: Allow](https://tools.ietf.org/html/rfc7231#section-7.4.1)

## Examples

### ✅ Good Response
```http
HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
Allow: GET, HEAD
```

### ❌ Bad Response
```http
HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
# Missing Allow header
```

