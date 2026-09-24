<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Validation Chain

## Description

Caches must validate stored responses using up-to-date validators.  When a server supplies an `ETag` or `Last-Modified` header, a well-behaved cache will include that validator in subsequent conditional requests (`If-None-Match` or `If-Modified-Since`).  The value in those request headers should match the most recently observed validator for the resource; if it does not, revalidation may fail and clients can receive stale or unexpected content.

This rule applies weak comparison semantics for entity-tags, meaning a weak ETag (`W/"tag"`) is considered equivalent to its strong counterpart when the opaque tag matches.

This rule examines the recorded history for the same client+resource and recomputes the current validator, taking into account updates that may arrive in `304 Not Modified` responses.

**The validator is the one of an entry this request could be revalidating**, not the newest one seen. RFC 9111 §4 lets a stored response answer a request only where the method allows it and the request presents the fields the response's `Vary` nominates, and §3 decides whether there was an entry at all. So a resource varied on `Accept-Encoding` with a tag per coding has one current validator per variant, and a request asking for gzip is compared against the gzip response's tag however recently the identity one arrived; a `no-store` answer, an `OPTIONS` answer, or a response no cache was licensed to keep does not replace the entry before it. A `304` does renew it: it is never stored itself, but it freshens the stored response it validated (§4.3.4).  If the current request contains a conditional header whose value does not match the known validator, a violation is raised.  The rule ignores requests that are not conditional and situations where no validator was ever seen.

## Violations

- [conditional_validator_conflicting](../violations/conditional_validator_conflicting.md) — A precondition names a validator older than the last one seen

## Specifications

- [RFC 9111 §4.3.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1): Sending a Validation Request — a cache builds preconditions from stored validators (entity tags MUST, Last-Modified SHOULD)
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): If-None-Match
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): If-Modified-Since

## Configuration

```toml
[rules.cache_validation_chain]
enabled = true
```

## Examples

### ✅ Good — the precondition names the newest validator

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abc"

> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "abc"
```

### ❌ Bad — a 304 renewed the validator, and the next precondition names the old one

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abc"

> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "abc"

< HTTP/1.1 304 Not Modified
< ETag: "xyz"

> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "abc"
```
