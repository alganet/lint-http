<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Range Request And Caching

## Description

A client that has been given a 206 (Partial Content) response holds a fragment of a representation, and the fragments can only be combined if they share the same strong validator.  When the stored response provided an entity tag, a cache validating it has to send that tag back — RFC 9111 §4.3.1 makes it a MUST, and names three fields that satisfy it: `If-Match`, `If-None-Match` or `If-Range`.

This rule tracks earlier transactions for the same client and resource.  After a 206, it reports a later `Range` request that carries none of those three fields, an `If-Range` holding a tag other than the one most recently provided for the resource, and an `If-Range` holding a date when an entity tag was provided (RFC 9110 §13.1.5 forbids the date in that case).  The validator compared against is the one from the most recent response carrying any, since a later 200 or 304 replaces what the client stores.

Where the stored response carried only a `Last-Modified` date the rule is silent: §4.3.1 asks for that date with a SHOULD that excludes subrange requests and a MAY that covers them, and neither makes its absence a defect.  Weak entity tags are skipped, because `If-Range` may not carry one and ranges sharing only a weak validator cannot be combined at all.

**What it assumes.** §4.3.1 is addressed to caches, and no field on the wire says whether a client is one.  A user agent that fetches consecutive ranges and stores nothing — a media player, a download manager streaming to disk — is under no obligation to send any of these fields, and this rule will report it. Two negotiated variants of one resource share a history here as well, since the query is keyed on the URI and not on the cache key §4.3.1 narrows to.  Turn the rule off for traffic that is not caching.

## Specifications

- [RFC 9111 §4.3.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1): The requirement, and it is a MUST: send the stored response's entity tags, using `If-Match`, `If-None-Match` **or** `If-Range`. The `Last-Modified` bullets are a SHOULD that excludes subranges and a MAY that covers them
- [RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5): `If-Range` precondition to `Range` requests, its exact-match comparison, and the MUST NOT against putting a date there while holding an entity tag. RFC 7233 §3.2 defined the field; RFC 9110 obsoleted RFC 7233, and this reference had not moved
- [RFC 9110 §15.3.7.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.3): Partial responses combine only when they share the same strong validator — the client-side premise, and the reason a weak tag is skipped
- [RFC 9111 §3.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-3.4): Combining partial content requires a shared strong validator
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): GET is the only method for which range handling is defined, which is what bounds this rule to GET

## Configuration

```toml
[rules.range_request_and_caching]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — the stored tag comes back in `If-Range`

```http
HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
If-Range: "etag123"
```

### ✅ Good — or in `If-None-Match`, which the same sentence allows

```http
HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
If-None-Match: "etag123"
```

### ✅ Good — a date-only stored response asks for nothing

```http
HTTP/1.1 206 Partial Content
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
```

### ❌ Bad — no precondition at all after a 206 that provided a tag

```http
HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
```

### ❌ Bad — `If-Range` holds a tag that was never provided

```http
HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
If-Range: "other"
```

### ❌ Bad — a date in `If-Range` while holding an entity tag

```http
HTTP/1.1 206 Partial Content
ETag: "etag123"
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Range: bytes 0-99/1000

GET /resource HTTP/1.1
Range: bytes=100-199
If-Range: Wed, 21 Oct 2015 07:28:00 GMT
```
