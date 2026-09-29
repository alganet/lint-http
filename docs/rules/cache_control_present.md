<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Cache-Control Present

## Description

This rule reports a `200 OK` response a cache could store that carries neither `Cache-Control` nor `Expires`. With neither, RFC 9111 §4.2.2 lets every cache assign the response a heuristic freshness lifetime of its own, estimated from other fields such as `Last-Modified`, so how long the response is reused is decided by each cache separately rather than by the origin.

The `Cache-Control` header is the primary mechanism for defining the caching policies of a resource. Even if a resource should not be cached, it is best practice to explicitly state this (e.g., `Cache-Control: no-store`) rather than relying on default browser behaviors or heuristic caching.

An `Expires` on its own is not reported. §4.2.1 takes `Expires` minus `Date` as an explicit freshness lifetime, and §5.3 has a recipient read an invalid `Expires` — the value `0` among them — as a time already past, so a response carrying one has specified its lifetime and left nothing to guess.

## Violations

- [cache_control_missing](../violations/cache_control_missing.md) — A 200 leaves its freshness lifetime to be guessed

## Specifications

- [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2): Calculating Heuristic Freshness — without an explicit expiration time a cache MAY assign one of its own, estimated from other field values
- [RFC 9111 §4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1): Calculating Freshness Lifetime — the order a cache consults `s-maxage`, `max-age` and `Expires` in, and what it may do when one directive is present more than once
- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3): `Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date ("0" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control
- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control — the header whose absence the rule reports

## Configuration

```toml
[rules.cache_control_present]
enabled = true
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

### ✅ Good (`Expires` alone — §4.2.1: an explicit lifetime, so nothing is left to guess)

```http
HTTP/1.1 200 OK
Date: Thu, 01 Jan 2026 00:00:00 GMT
Expires: Fri, 02 Jan 2026 00:00:00 GMT
Content-Type: application/json
```

### ❌ Bad Response with no Cache-Control field line

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

### ✅ Good (OPTIONS — §9.3.7: no cache stores it, so none guesses at it)

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Allow: GET, HEAD, OPTIONS
```

### ✅ Good (POST — §9.3.3 gives a POST response no heuristic to take away)

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
```
