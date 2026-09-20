<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Status and Caching Semantics

## Description

Responses with certain status codes are heuristically cacheable (for example: `200`, `203`, `204`, `206`, `300`, `301`, `308`, `404`, `405`, `410`, `414`, `501`). A response on any other status is stored only if it says something that licenses storing it: explicit freshness (`Cache-Control: max-age=<seconds>` / `Cache-Control: s-maxage=<seconds>` or an `Expires` header), or a `public` or `private` directive — which licenses storage on its own and lets a cache calculate the lifetime heuristically.

This rule warns when a response status that is not heuristically cacheable says none of those, so no cache may keep it. It stays silent where a lifetime would not help: `no-store` on either message, an interim status, and a method that defines no caching semantics.

## Violations

- [cache_control_freshness_missing](../violations/cache_control_freshness_missing.md) — A status no cache stores by default states no freshness

## Specifications

- [RFC 9111 §3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3): Storing Responses in Caches (the licences to store a response: public, private, Expires, max-age, s-maxage, a cache extension, or a heuristically cacheable status)
- [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1): Overview of Status Codes — the status codes defined as heuristically cacheable, which is the set a response outside it has to state its own freshness to join

## Configuration

```toml
[rules.status_and_caching_semantics]
enabled = true
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

### ✅ Good (`public` licenses storing it without a lifetime, and §4.2.2 lets the cache calculate one)

```http
HTTP/1.1 302 Found
Cache-Control: public
Location: https://example.org/
```

### ✅ Good (`no-store` fails an earlier term of §3, so no lifetime would make a cache keep it)

```http
HTTP/1.1 302 Found
Cache-Control: no-store
Location: https://example.org/
```

### ❌ Bad

```http
HTTP/1.1 302 Found
Location: https://example.org/
```

### ✅ Good (OPTIONS — §9.2.3 defines no caching semantics for it, so no freshness would store it)

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 403 Forbidden
```

### ❌ Bad (POST — §9.3.3 makes explicit freshness half of what would store it)

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 403 Forbidden
```
