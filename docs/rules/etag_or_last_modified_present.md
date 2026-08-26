<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server ETag or Last-Modified Present

## Description

This rule checks if `200 OK` responses include either an `ETag` or a `Last-Modified` header.

These headers act as validators, allowing clients to perform conditional requests (`If-None-Match` or `If-Modified-Since`). This enables efficient caching and revalidation, significantly reducing bandwidth when resources haven't changed.

## Specifications

- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation: an origin server SHOULD send Last-Modified
- [RFC 9110 §8.8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.1): Generation: an origin server SHOULD send an ETag

## Configuration

```toml
[rules.etag_or_last_modified_present]
enabled = true
severity = "info"
```

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
