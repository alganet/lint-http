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
two responses disagree about which version of the resource is current.

A `Date` names when a message was sent and no version, so a response timed
only by `Date` is reported only when it is stale by its own terms: it carries
`Age`, which a cache MUST write when it serves a stored response unvalidated,
and it states a lifetime (`max-age`, `s-maxage`, `Expires`, or a bare
`no-cache`) that its age has run past.  Without `Age` the response was
generated for its own request, and two of those out of order are two servers'
clocks; with `Age` and no lifetime, a cache may have assigned one
heuristically.  The finding says which field it read, quotes both values, and
says whether the later response carried `Age`, since a cache holding an old
copy and two servers that disagree are two different repairs.

The two headers are never compared with each other.  `Last-Modified` is when
the representation was edited and `Date` is when the message was sent, so the
first is at or before the second in any one response; comparing across them
reports a page whose siblings simply omit `Last-Modified` as stale.

Only transactions whose response contains a parseable HTTP-date are
examined; missing or unparseable headers are ignored.  Only a 200 or a 206
answering a GET or a HEAD joins the timeline, on either side of the
comparison.  Those carry the resource; a 3xx, a 4xx, a 5xx, a 204 or a 304
is generated when the request arrives and so dates the asking, and even a
200 represents the communication options rather than the resource when it
answers an OPTIONS, or our own request when it answers a TRACE.  Reading
one of those as a previous observation raises the timeline to *now* and
reports every later cache hit — which correctly carries the stored
response's older Date — as stale.

A previous response is compared only when its `Vary` nominates nothing the
two requests wrote differently.  Two encodings of one page are two stored
entries, and the timestamps of one say nothing about the freshness of the
other.

A response that carries the terms of §4.2's definition is judged by the
definition rather than by the timeline.  Where `max-age`, `s-maxage` or
`Expires` gives a freshness lifetime and `Age` or `Date` gives a current
age, a lifetime that exceeds the age makes the response fresh, and a fresh
response is one every cache on the path was permitted to serve — a cache
hit under `max-age=600` with `Age: 31` is not stale because a sibling node
handed over a newer copy five seconds earlier.  Such a response is not
reported.  One whose age has run past its lifetime, or one timed by
`Last-Modified` that advertises no lifetime at all, is reported by the
timeline as before.

## Violations

- [cache_response_conflicting](../violations/cache_response_conflicting.md) — Two responses for one URI disagree about which version is current

## Specifications

- [RFC 9111 §4.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4): Serving Stale Responses — a cache MUST NOT generate one unless it is disconnected or a client or origin server explicitly permitted it
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2): Freshness — a response is fresh while its freshness lifetime exceeds its current age, and a fresh response is one a cache may serve
- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Vary — the cache key's second half, so two variants are two timelines
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): Last-Modified — the representation's modification time (preferred signal)
- [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1): Date — the message's origination time (coarser fallback signal)
- [RFC 9110 §15.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1): 200 OK — what its content represents depends on the request method
- [RFC 9111 §4.3.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.5): HEAD answers as the GET would have, so it dates the same resource
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

### ✅ Good — out‑of‑order `Date` from two servers

```http
< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 08:28:00 GMT

< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 08:27:51 GMT    # no Age: another server's clock
```

### ❌ Bad — a stored copy past its lifetime, behind a newer `Date`

```http
< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 08:28:00 GMT
< Cache-Control: max-age=60

< HTTP/1.1 200 OK
< Date: Wed, 21 Oct 2015 07:28:00 GMT
< Cache-Control: max-age=60
< Age: 3700    # served from storage, stale
```

### ❌ Bad — `Last-Modified` decreases

```http
< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 08:28:00 GMT

< HTTP/1.1 200 OK
< Last-Modified: Wed, 21 Oct 2015 07:00:00 GMT    # stale copy
```
