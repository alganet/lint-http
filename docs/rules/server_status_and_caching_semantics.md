<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Status and Caching Semantics

## Description

Responses with certain status codes are cacheable by default (for example: `200`, `203`, `204`, `206`, `300`, `301`, `308`, `404`, `405`, `410`, `414`, `501`). For other status codes to be cacheable, servers MUST include explicit freshness information such as `Cache-Control: max-age=<seconds>` / `Cache-Control: s-maxage=<seconds>` or an `Expires` header.

This rule warns when a response status that is not cacheable by default does not include explicit freshness information.

## Specifications

- [RFC 9111 §3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3): Storing Responses in Caches (the freshness signals a cache requires: Expires, max-age, s-maxage, or a heuristically cacheable status)
- [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1): Overview of Status Codes (which status codes are defined as heuristically cacheable)

## Configuration

```toml
[rules.server_status_and_caching_semantics]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 302 Found
Cache-Control: max-age=60
Location: https://example.org/
```

```http
HTTP/1.1 503 Service Unavailable
Expires: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
HTTP/1.1 302 Found
Location: https://example.org/
```
