<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful no-store enforcement

## Description

The `no-store` cache-control directive (RFC 9111 §5.2.2.3) tells caches that
**they must not retain any part of the response or request**.  A cache that
breaks this rule may later reuse stale or private data inappropriately.

This stateful rule observes the history of a particular client+resource and
remembers which validator values (ETag or Last-Modified) were seen on
responses that carried `Cache-Control: no-store`.  Only the most recent
occurrence of each validator is kept; if the same value later appears on a
non‑`no-store` response it is no longer considered forbidden.  When the
current request carries a conditional header whose value matches one of those
"no-store" validators, we infer that the response must have been stored at
some point, and a violation is reported.

The check is scoped to resource histories (the engine filters transactions by
URI) and therefore does not attempt to reason about unrelated traffic.  The
rule does not flag unconditional requests, nor does it attempt to detect
improper storage of requests (which is rarely visible from traffic capture).

## Specifications

- [RFC 9111 §5.2.2.3 — `no-store`](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.3)
- [RFC 9111 §4.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3) — Expiration model (validators are used for revalidation)

## Configuration

```toml
[rules.stateful_no_store_enforcement]
enabled = true
severity = "warn"
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

The mere presence of an ETag does not trigger a warning if a subsequent
response for the same resource did not include `no-store`.

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
