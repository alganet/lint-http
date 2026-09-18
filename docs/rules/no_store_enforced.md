<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful no-store enforcement

## Description

The `no-store` cache-control directive (RFC 9111 §5.2.2.5) tells caches that **they must not retain any part of the response or request**.  A cache that breaks this rule may later reuse stale or private data inappropriately.

This stateful rule observes the history of a particular client+resource and remembers which validator values (ETag or Last-Modified) were seen on responses that carried `Cache-Control: no-store`.  A validator counts as forbidden only if **no** exchange the client was allowed to store ever offered it. The most recent occurrence used to decide, and that read a `max-age=60` response handing over `ETag: "a"` and a later `no-store` response carrying the same tag as a client stealing what it had been licensed to keep: §5.2.2.5 forbids storing *that* response and evicts nothing already held. So the sets are subtracted rather than raced, and "allowed to store" counts the directive on the earlier request (§5.2.1.5) as well as the one on its response. `Last-Modified` values are subtracted by both spelling and instant, since the match below compares both.  When the current request carries a conditional header whose value matches one of those "no-store" validators, we infer that the response must have been stored at some point, and a violation is reported.

The check is scoped to resource histories (the engine filters transactions by URI) and therefore does not attempt to reason about unrelated traffic.  The rule does not flag unconditional requests, nor does it attempt to detect improper storage of requests (which is rarely visible from traffic capture).

## Violations

- [cache_control_no_store_ignored](../violations/cache_control_no_store_ignored.md) — A validator from a no-store response comes back on a later request

## Specifications

- [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5): `no-store` — a cache MUST NOT store any part of the request or the response, and MUST NOT use the response to satisfy another request
- [RFC 9111 §4.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3): Validation (conditional requests carry the validators this rule tracks)

## Configuration

```toml
[rules.no_store_enforced]
enabled = true
```

## Examples

### ✅ Good — no reuse

```http
> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-store
< ETag: "a"

# later the client issues a fresh request with no conditional headers;
# since there is nothing to compare the rule does not fire.
> GET /foo HTTP/1.1
> Host: example.com
```

### ✅ Good — validator later refreshed without no-store

```http
< HTTP/1.1 200 OK
< Cache-Control: no-store
< ETag: "a"

< HTTP/1.1 200 OK
< Cache-Control: max-age=60
< ETag: "a"

> GET /foo HTTP/1.1
> Host: example.com
> If-None-Match: "a"    # this value now comes from a cacheable response
```

### ❌ Bad — conditional request referencing a no-store response

```http
< HTTP/1.1 200 OK
< Cache-Control: no-store
< ETag: "x"

> GET /foo HTTP/1.1
> Host: example.com
> If-None-Match: "x"    # validator derived from a no-store entry
```

```http
< HTTP/1.1 200 OK
< Cache-Control: no-store
< Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT

> GET /foo HTTP/1.1
> Host: example.com
> If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT
```
