<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful immutable cache never stale

## Description

The `immutable` cache-control directive (RFC 8246) signals that the
representation is not expected to change.  Clients and caches are therefore
encouraged to treat the response as fresh for the duration of its advertised
freshness lifetime and to avoid revalidation during that period.  Revalidating
(issuing a conditional request) while the entry is still fresh is wasteful and
undermines the purpose of `immutable`.

This rule reconstructs a small piece of cache state for a given client and
resource by locating the most recent prior response bearing an `immutable`
directive that does not simultaneously forbid caching (`no-store` or
`no-cache`).  It estimates the "age" of that response using any `Age` header
and the elapsed time since the response was observed.  The advertised freshness
lifetime is computed using the shared helper in `helpers::headers`, which
honours `Cache-Control: max-age` and falls back to an `Expires` header if
necessary.  If a subsequent request for the same resource includes a
conditional header (`If-None-Match` or `If-Modified-Since`) **and** the
calculated age is still less than the freshness lifetime, a warning is
produced.  Unconditional requests and conditional requests made after the
freshness lifetime expires are permitted, since `immutable` entries may still
be reused without revalidation once stale.

## Specifications

- [RFC 8246 §3 — "immutable" directive](https://datatracker.ietf.org/doc/html/rfc8246#section-3)
- [RFC 9111 §4.2/§4.3 — Calculating age and expiration](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2)

## Configuration

```toml
[rules.stateful_immutable_cache_never_stale]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — fresh response reused without revalidation

```http
> GET /static.css HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=3600, immutable

# thirty seconds later the cache is still fresh; no conditional request is sent
```

### ✅ Good — conditional request after expiry is allowed

```http
> GET /static.css HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, immutable
< ETag: "v1"

# later, after expiry:
> GET /static.css HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # revalidation after freshness is fine
```

### ❌ Bad — unnecessary revalidation while still fresh

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=600, immutable
< ETag: "a"

# still within the advertised lifetime
> GET /image.png HTTP/1.1
> Host: example.com
> If-None-Match: "a"        # unnecessary conditional request
```
