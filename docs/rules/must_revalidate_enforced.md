<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful must-revalidate enforcement

## Description

The `must-revalidate` cache-control directive (RFC 9111 §5.2.2.2) tells caches that once a stored response becomes stale it **must not** be used to satisfy subsequent requests unless the entry has been successfully revalidated with the origin server.  Serving a stale value without revalidation can expose clients to outdated or incorrect data.

This rule reconstructs a small piece of cache state for a given client+resource by locating the most recent prior response that included `Cache-Control: must-revalidate`.  The request now presented must be one that stored response was allowed to answer in the first place (§4): the same method, or a `HEAD` against a stored `GET`, presenting the same selecting header fields under the response's `Vary` (§4.1) — an entry stored for one variant could not have answered a request for another, so no validator was declined. A response no cache was allowed to keep at all is no entry either, whatever validator or directive it carries: §3 also asks that the status be final and that the response advertise a freshness lifetime, or be `public` or `private`, or have a status defined as heuristically cacheable — a `412` with an `ETag` satisfies none of those, and the search reads past it.  Only GET, HEAD and POST have caching semantics at all, so a response to an `OPTIONS` or a `TRACE` is no stored entry even against a later request of its own method.  A stored `GET` is likewise no candidate for an `OPTIONS`, a `TRACE`, or an unsafe method, and where nothing could have been reused there is no reuse to report.  It estimates the age of that entry using the `Age` header (if any) plus the time elapsed since the response was observed. The advertised freshness lifetime is taken from a `max-age` directive, if present, or else from an `Expires` header; replies that provide neither are considered immediately stale.  If the computed age exceeds or **equals** the freshness lifetime (a zero lifetime is therefore immediately stale) *and* the current request is unconditional and the original response carried a validator, the rule raises a warning. Unconditional here means carrying none of `If-None-Match`, `If-Modified-Since` or `If-Range`: the last is a third place to send the very entity tag the entry holds (RFC 9110 §13.1.5 writes `If-Range = entity-tag / HTTP-date`, and a client that has a tag must put that there rather than a date), so a client resuming a download has sent its validator and is not withholding one.  Directive names in `Cache-Control` are parsed case-insensitively, so `Max-Age` or `MAX-AGE` are treated the same as the canonical lowercase form.  Clients that lack validators are not flagged because they have no way to revalidate.

**The reuse the directive forbids is not what this reads.** §5.2.2.2 binds a cache, and this implementation watches the wire between a client and an origin: had the client's cache reused the stale entry, no request would have crossed it. Every finding here therefore sits on a request the cache did *not* satisfy — the directive honoured — and what it reports is the narrower fact the wire carries, that a validator the client held went unsent and a full body came back where a `304` would have served. The level follows: a `warn` whose obligation is unstated, because the `MUST NOT` binds the cache and not the client the finding names. **And the saving has to be one this exchange could have made.** A `304` stands in for a `200` and for nothing else (RFC 9110 §15.4.5), so a request the origin refused — a `412`, a `400`, anything that never reached the representation — resent no body for a validator to have spared; and a `HEAD` answer carries no content at any status (RFC 9110 §9.3.2), so there too the precondition would have bought nothing. On those shapes the rule is silent, because the sentence would otherwise name a body that never crossed the wire. **And § 3 comes before § 4.** A prior response carrying `no-store` is one no cache was permitted to store, so there is no entry for the later request to have reused and no validator the client could have sent; the search skips such a response rather than stopping at it, because an entry an earlier exchange left is still stored. The directive on the earlier request has the same effect (RFC 9111 §5.2.1.5). `no-cache, no-store, must-revalidate` is one of the commonest `Cache-Control` lines on the web, and while it drew this finding there was no request a client could make that drew nothing: sending the validator instead draws `cache_control_no_store_ignored`.

This stateful check complements the existing `max_age_directive_valid` rule by covering situations where `must-revalidate` is present but no explicit `max-age` is provided (stale data is prohibited immediately), and by emphasising the intent of the `must-revalidate` directive when both rules are enabled.

## Violations

- [cache_control_must_revalidate_ignored](../violations/cache_control_must_revalidate_ignored.md) — A stale must-revalidate response is re-requested without its validator

## Specifications

- [RFC 9111 §5.2.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2): `must-revalidate` — once the response is stale, a cache MUST NOT reuse it until it has been successfully validated by the origin
- [RFC 9110 §9.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.3): Methods and Caching (which methods leave a stored response behind at all)
- [RFC 9111 §4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4): Constructing Responses from Caches (which stored response may answer a presented request)
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2): Freshness (a response is stale once its age reaches its freshness lifetime)
- [RFC 9111 §4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3): Calculating Age (the response age this rule estimates)
- [RFC 9111 §4.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3): Validation (revalidating a stale entry before reuse)

## Configuration

```toml
[rules.must_revalidate_enforced]
enabled = true
```

## Examples

### ✅ Good — fresh entry reused without conditional headers

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60, must-revalidate

# thirty seconds later the cache is still fresh and may satisfy a request
# without conditional headers.  The linter does not observe a violation.
```

### ✅ Good — stale entry revalidated

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# later, after expiry:
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used
```

### ✅ Good — must-revalidate with no freshness never reused

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: must-revalidate
< ETag: "v2"

# client must revalidate on every request; a conditional request is fine
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v2"
```

### ✅ Good — a method the stored entry could not have answered

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# later, after expiry, a different method on the same resource:
> OPTIONS /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 405 Method Not Allowed

# no cache answers an OPTIONS from a stored GET, so nothing was reused
```

### ✅ Good — the validator sent, as If-Range

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"
< Accept-Ranges: bytes

# later, the client resumes with the tag it was handed:
> GET /resource HTTP/1.1
> Host: example.com
> Range: bytes=0-9
> If-Range: "v1"

< HTTP/1.1 200 OK
< ETag: "v2"

# If-Range carries the entity tag, so the client sent its validator; that
# the tag no longer matches is why a whole representation came back
```

### ✅ Good — a request the origin refused, so no body was resent

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# later, after expiry, an If-Match the origin declines:
> GET /resource HTTP/1.1
> Host: example.com
> If-Match: "other"

< HTTP/1.1 412 Precondition Failed

# the origin never reached the representation, so nothing was resent and
# no 304 could have replaced what came back
```

### ✅ Good — a HEAD, whose answer carries no content either way

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# later, after expiry, the client asks for metadata only:
> HEAD /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK

# a HEAD response sends no content, so the validator would have spared
# no body and there is no saving to report
```

### ❌ Bad — a stale entry's validator held back

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# several seconds later the client fetches again but omits validators
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# violation: the client held "v1" for a stale must-revalidate entry and
# asked again without it, so a full body came back where a 304 would have done
```
