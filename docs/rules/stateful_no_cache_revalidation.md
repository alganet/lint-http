<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful no-cache revalidation

## Description

The `no-cache` cache-control directive (RFC 9111 §5.2.2.5) permits a cache to
store a response, but it **must not** use that stored entry to satisfy a
subsequent request without first validating it with the origin server.  In
practice, caches are expected to issue a conditional request using a validator
(usually an `ETag` or `Last-Modified` value) when they have one; if no validator
is available the cache may perform an unconditional request, which still
contacts the origin server.

This stateful rule reconstructs a small portion of cache state for the current
client+resource by locating the most recent prior response that included
`Cache-Control: no-cache`.  If that response also carried a validator and the
current request is unconditional (no `If-None-Match` or `If-Modified-Since`
headers), the rule emits a warning.  The presence of validators is required to
avoid false alarms in cases where the entry could not possibly be revalidated.

The check deliberately ignores request-side `Cache-Control: no-cache` clauses
and makes no attempt to calculate freshness; it simply tracks whether a
conditional header was omitted.  This rule complements
`stateful_max_age_directive_validity` and
`stateful_must_revalidate_enforcement` by focussing on the specific behaviour
mandated by the `no-cache` directive.

## Specifications

- [RFC 9111 §5.2.2.5 — `no-cache`](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5)
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2) — Calculating the age of a response (background context)

## Configuration

```toml
[rules.stateful_no_cache_revalidation]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — conditional request satisfies no-cache requirement

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache
< ETag: "v1"

# later:
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used; no violation
```

### ✅ Good — no validator means unconditional request is acceptable

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache

# client cannot compose a conditional request; unconditional fetch is fine
> GET /resource HTTP/1.1
> Host: example.com
```

### ❌ Bad — reused entry without revalidation

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache
< ETag: "v1"

# later, client repeats request but omits validator
> GET /resource HTTP/1.1
> Host: example.com
# violation: cached response required conditional revalidation
```