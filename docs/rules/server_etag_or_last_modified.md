<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server ETag or Last-Modified Present

## Description
This rule checks if `200 OK` responses include either an `ETag` or a `Last-Modified` header.

These headers act as validators, allowing clients to perform conditional requests (`If-None-Match` or `If-Modified-Since`). This enables efficient caching and revalidation, significantly reducing bandwidth when resources haven't changed.

## Specifications
- [RFC 7232, Section 2.1: Weak and Strong Validators](https://tools.ietf.org/html/rfc7232#section-2.1)
- [RFC 7232, Section 2.2: Last-Modified](https://tools.ietf.org/html/rfc7232#section-2.2)
- [RFC 7232, Section 2.3: ETag](https://tools.ietf.org/html/rfc7232#section-2.3)

## Examples

### ✅ Good Response (ETag)
```http
HTTP/1.1 200 OK
Content-Type: image/png
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### ✅ Good Response (Last-Modified)
```http
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad Response
```http
HTTP/1.1 200 OK
Content-Type: image/png
# Missing both ETag and Last-Modified
```
