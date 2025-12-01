<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Cache-Control Present

## Description
This rule checks if `200 OK` responses include a `Cache-Control` header.

The `Cache-Control` header is the primary mechanism for defining the caching policies of a resource. Even if a resource should not be cached, it is best practice to explicitly state this (e.g., `Cache-Control: no-store`) rather than relying on default browser behaviors or heuristic caching.

## Specifications
- [RFC 7234, Section 5.2: Cache-Control](https://tools.ietf.org/html/rfc7234#section-5.2)

## Examples

### ✅ Good Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

### ❌ Bad Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
# Missing Cache-Control header
```
