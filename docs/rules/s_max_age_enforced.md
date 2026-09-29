<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful s-maxage Enforcement

## Description

Responses that include a `Cache-Control: s-maxage=<seconds>` directive are intended to limit how long **shared** caches may consider the representation fresh.  Private caches (e.g. in a browser or single-client proxy) **must ignore** `s-maxage` and instead rely on the ordinary freshness lifetime (`max-age`, `Expires`, heuristics, etc.).  Misinterpreting `s-maxage` on the client side can lead to unnecessary conditional requests and wasted network traffic.

This rule watches a series of transactions from the same client and examines the most recent prior response for the same resource that carried both an `<s-maxage>` value and a larger `max-age`.  If the client subsequently issues a conditional request **after** the `s-maxage` interval but **before** the `max-age` interval has elapsed, the cached entry was still fresh according to the private-cache semantics and revalidation was premature.  A warning is issued in that case.

A request that refused the entry itself is not reported: `no-cache` (or `Pragma: no-cache` with no `Cache-Control`), a `max-age` the entry has outlived, or a `min-fresh` the private lifetime cannot meet (RFC 9111 §5.2.1). Such a request has stated why it revalidated, and it was not `s-maxage`.

## Violations

- [cache_control_s_maxage_ignored](../violations/cache_control_s_maxage_ignored.md) — A cache that s-maxage does not address used it for freshness

## Specifications

- [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10): `s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache

## Configuration

```toml
[rules.s_max_age_enforced]
enabled = true
```

## Examples

### ✅ Good — a variant this request did not select

```http
> GET /resource HTTP/1.1
> Host: example.com
> Accept-Encoding: gzip

< HTTP/1.1 200 OK
< Cache-Control: max-age=3600, s-maxage=60
< Vary: Accept-Encoding
< ETag: "v1"

# after 120s, the same resource asked for without a coding preference:
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"

# the entry holding both directives is the gzip variant, which could not have
# answered this request, so no cache read s-maxage as its freshness limit
```

### ✅ Good — a request that refused the entry itself

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=3600, s-maxage=60
< Age: 120
< ETag: "v1"

# a reload, after s-maxage and inside max-age
> GET /resource HTTP/1.1
> Host: example.com
> Cache-Control: max-age=0
> If-None-Match: "v1"

# the request says why it revalidated, and it was not s-maxage
```

### ❌ Bad — premature revalidation based on `s-maxage`

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=3600, s-maxage=60
< ETag: "v1"

# seconds later, same client revalidates after 120s (s-maxage expired but
# max-age still valid)
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"
```
