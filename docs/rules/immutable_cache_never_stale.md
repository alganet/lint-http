<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful immutable cache never stale

## Description

The `immutable` cache-control directive (RFC 8246) signals that the representation is not expected to change.  Clients and caches are therefore encouraged to treat the response as fresh for the duration of its advertised freshness lifetime and to avoid revalidation during that period.  Revalidating (issuing a conditional request) while the entry is still fresh is wasteful and undermines the purpose of `immutable`.

This rule reconstructs a small piece of cache state for a given client and resource by locating the most recent prior response bearing an `immutable` directive that does not simultaneously forbid caching (`no-store` or `no-cache`).  It estimates the "age" of that response using any `Age` header and the elapsed time since the response was observed.  The advertised freshness lifetime is computed using the shared helper in `helpers::headers`, which honours `Cache-Control: max-age` and falls back to an `Expires` header if necessary.  If a subsequent request for the same resource includes a conditional header (`If-None-Match` or `If-Modified-Since`) **and** the calculated age is still less than the freshness lifetime, a warning is produced.  Unconditional requests and conditional requests made after the freshness lifetime expires are permitted, since `immutable` entries may still be reused without revalidation once stale.

**A reload is still reported, and a force reload is not.** RFC 8246 §2 names a reload as a case in which the client should still not revalidate, so a request carrying `Cache-Control: max-age=0` is reported like any other. The exception it makes is an explicit override by the user, such as a force reload, which reaches the wire as a request `no-cache` (or `Pragma: no-cache` with no `Cache-Control`).

## Violations

- [cache_control_immutable_ignored](../violations/cache_control_immutable_ignored.md) — A still-fresh immutable response is revalidated anyway

## Specifications

- [RFC 8246 §2](https://www.rfc-editor.org/rfc/rfc8246.html#section-2): `immutable` — clients SHOULD NOT revalidate during the response's freshness lifetime, and the extension applies during that lifetime only, so a response with none is outside it entirely
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2): Freshness — Calculating Freshness Lifetime (§4.2.1) and Calculating Age (§4.2.3)

## Configuration

```toml
[rules.immutable_cache_never_stale]
enabled = true
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

### ✅ Good — a method the stored entry could not have answered

```http
> OPTIONS /asset.js HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=31536000, immutable

# later, a GET for the same resource:
> GET /asset.js HTTP/1.1
> Host: example.com
> If-None-Match: "v1"

# no cache stores an OPTIONS response, so nothing promised this GET that the
# representation would not change and nothing was revalidated against it
```

### ✅ Good — a force reload, which the user asked for

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=600, immutable
< ETag: "a"

# the user forces a reload
> GET /image.png HTTP/1.1
> Host: example.com
> Cache-Control: no-cache
> If-None-Match: "a"
```

### ❌ Bad — a plain reload is still owed no revalidation

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=600, immutable
< Age: 5
< ETag: "a"

# the user reloads
> GET /image.png HTTP/1.1
> Host: example.com
> Cache-Control: max-age=0
> If-None-Match: "a"
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
