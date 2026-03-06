<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Semantic Cache Coherence

## Description

Cache coherence ensures that once a newer representation of a resource is
available, earlier (stale) copies are not inadvertently served without
revalidation or invalidation.  Misconfigured caches or origin servers may
return an older version of a document after a newer one has been observed.

This rule reconstructs a simple timeline for each resource observed by the
client.  Each response is assigned a timestamp derived from its
`Last-Modified` header if present, otherwise from the `Date` header.  If a
subsequent response for the *same URI* carries a timestamp that is strictly
older than one seen previously, we report a violation — the later response
appears to be serving a stale representation.

Only transactions whose response contains a parseable HTTP-date are
examined; missing or unparseable headers are ignored.  304 Not Modified
responses are skipped since they do not convey a new representation.

## Specifications

- [RFC 9111 §6 — Cache coherence](https://www.rfc-editor.org/rfc/rfc9111.html#section-6)

## Configuration

```toml
[rules.semantic_cache_coherence]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

A newer response has a later `Date` header; no violation is raised.

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
