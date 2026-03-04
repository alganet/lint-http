<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful max-age directive validity

## Description

Responses tagged with a `Cache-Control` `max-age=<seconds>` directive
promise that the representation may safely be reused without revalidation for
`<seconds>` seconds after it was stored.  Caches and clients that ignore this
lifespan risk serving stale content or incurring unnecessary round‑trips.

This rule reconstructs a very small piece of cache state for a given
client+resource by examining the most recent prior response that included a
parseable `max-age` directive.  It then computes an approximate "age" for that
stored response using any `Age` header it carried plus the time elapsed since
it was observed.

Two types of violations are reported:

* Sending a **conditional request** (`If-None-Match` or `If-Modified-Since`)
  while the cached copy is still fresh (age < max‑age).  Revalidation at this
  point is redundant and indicates the freshness lifetime is not being
  respected.
* Issuing an **unconditional request** after the cached entry has become stale
  (age > max‑age) *when the prior response provided a validator (ETag or
  Last-Modified)*.  In that case the cache should have revalidated first.
  (Clients that lack a validator are simply forced to fetch anew, which is not
  flagged.)

The stateful check augments the stateless
[`client_cache_respect`](client_cache_respect.md) rule, which merely
ensures conditional headers are included when validators exist regardless of
age.

## Specifications

- [RFC 9111 §4.2 — Calculating the age of a response](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2)
- [RFC 9111 §4.3 — Expiration model (freshness lifetime)](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3)

## Configuration

```toml
[rules.stateful_max_age_directive_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — fresh entry reused without conditional headers

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60

# thirty seconds later, no request is even sent (cache hit), so linter
# never observes a transaction.  If a request were visible, it would not
# include conditional headers during the freshness window.
```

### ✅ Good — stale entry revalidated

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1
< ETag: "v1"

# later, after expiry:
> GET /data HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used
```

### ❌ Bad — unnecessary revalidation while still fresh

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60
< ETag: "v1"

# ten seconds later, client inexplicably revalidates
> GET /data HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # age 10 < 60, should not revalidate yet
```

### ❌ Bad — stale entry reused without conditional request

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1
< ETag: "v1"

# several seconds later the client fetches again but omits validators
> GET /data HTTP/1.1
> Host: example.com
# violation: stale age but no conditional header
```