<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Vary Header Cache Validity

## Description

Caches use the response's `Vary` header to decide which request header
values must be incorporated into their cache key.  When a cached
representation is reused (for example via conditional requests using
`If-None-Match` or `If-Modified-Since`), the values of *all* headers
listed in `Vary` **must** be identical to those that produced the stored
response.  Otherwise the cache is effectively using an incomplete key and
may send a stale or incorrect representation to the server or client.

This rule inspects conditional requests and attempts to pair them with the
prior response whose validator is being reused.  If that earlier response
included a `Vary` header, the rule compares the request header values from
the two transactions.  Any difference is reported as a violation because it
indicates the cache key omitted a required dimension.

The rule is intentionally forgiving:

* It only applies when a previous validator matching the current
  conditional header can be located.
* `Vary: *` is ignored, since it precludes reuse and offers no explicit
  fields to compare.
* When no `Vary` header is present on the candidate response, no check is
  performed.

## Specifications

- [RFC 9111 §4.1 "How a Cache Calculates a Secondary Key"](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1)

## Configuration

```toml
[rules.stateful_vary_header_cache_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

A conditional request matches the original `Accept-Encoding` header value
from the cached response's request.

```http
> GET /resource HTTP/1.1
> Host: example.com
> Accept-Encoding: gzip
>
< HTTP/1.1 200 OK
< Vary: Accept-Encoding
< ETag: "v1"

> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"
> Accept-Encoding: gzip
```

### ❌ Bad — Vary dimension changed on revalidation

The client reuses the validator but has modified the `Accept-Encoding`
value.  A cache key that ignored this header would select the wrong
entry for the later request.

```http
> GET /resource HTTP/1.1
> Host: example.com
> Accept-Encoding: gzip
>
< HTTP/1.1 200 OK
< Vary: Accept-Encoding
< ETag: "v1"

> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"
> Accept-Encoding: deflate    # mismatch from original request
```

### ✅ Good — non-conditional request

The rule only applies when a conditional validator is present.

```http
> GET /resource HTTP/1.1
> Host: example.com
> Accept-Encoding: gzip
```

```http
< HTTP/1.1 200 OK
< Vary: Accept-Encoding
< ETag: "v1"
```
