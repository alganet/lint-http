<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Coherence

## Description

Cache coherence ensures that once a newer representation of a resource is
available, earlier (stale) copies are not inadvertently served without
revalidation or invalidation.  Misconfigured caches or origin servers may
return an older version of a document after a newer one has been observed.

This rule reconstructs a simple timeline for each resource observed by the
client.  Each response is assigned a timestamp derived from its
`Last-Modified` header if present, otherwise from the `Date` header.  If a
subsequent response for the *same URI* carries a timestamp that is strictly
older than one seen previously *on that same header*, we report a violation —
the later response appears to be serving a stale representation.

The two headers are never compared with each other.  `Last-Modified` is when
the representation was edited and `Date` is when the message was sent, so the
first is at or before the second in any one response; comparing across them
reports a page whose siblings simply omit `Last-Modified` as stale.

Only transactions whose response contains a parseable HTTP-date are
examined; missing or unparseable headers are ignored.  Only a 200 or a 206
joins the timeline, on either side of the comparison: those carry the
resource, while a 3xx, a 4xx, a 5xx, a 204 or a 304 is generated when the
request arrives and so dates the asking rather than the resource.  Reading
one of those as a previous observation raises the timeline to *now* and
reports every later cache hit — which correctly carries the stored
response's older Date — as stale.

## Violations

- [cache_response_conflicting](../violations/cache_response_conflicting.md) — Two responses for one URI disagree about which version is current

## Specifications

- [RFC 9111 §4.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4): Serving Stale Responses — a cache MUST NOT generate one unless it is disconnected or a client or origin server explicitly permitted it
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): Last-Modified — the representation's modification time (preferred signal)
- [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1): Date — the message's origination time (coarser fallback signal)
- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content — parts of the same selected representation, so it dates it
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — conveys no representation, so it dates nothing
- [RFC 9110 §15.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5): 4xx Client Error — the representation explains the error, not the resource

## Configuration

```toml
[rules.cache_coherence]
enabled = true
```

## Examples

### ✅ Good

```http
> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 07:28:00 GMT

> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 08:28:00 GMT
```

### ✅ Good — using `Last-Modified`

```http
< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 08:28:00 GMT

< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 09:00:00 GMT
```

### ❌ Bad — out‑of‑order `Date`

```http
< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 08:28:00 GMT

< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 07:28:00 GMT    # older than previous
```

### ❌ Bad — `Last-Modified` decreases

```http
< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 08:28:00 GMT

< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 07:00:00 GMT    # stale copy
```
