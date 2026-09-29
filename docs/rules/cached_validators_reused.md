<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cached Validators Reused

## Description

This rule checks if the client correctly uses conditional headers (`If-None-Match`, `If-Modified-Since`, or `If-Range`) when re-requesting a resource it has previously fetched.

**A request carrying any precondition is not one sent with none.** `If-Match` and `If-Unmodified-Since` ask for a `412` rather than a `304`, and a client that wrote either conditioned on the validator it was given, so the rule stays silent on them too; the entry it reports is the request that reused nothing.

If a server provides validators (like `ETag` or `Last-Modified`) in a response, a well-behaved client should use them in subsequent requests for the same resource to allow the server to return a `304 Not Modified` response, saving bandwidth and processing time.

**Only an answer a `304` could have replaced is reported.** A `304` stands in for a `200` to a `GET` (RFC 9110 §15.4.5) and for nothing else. A `HEAD` answer carries no content to spare, and §4.3.5 of RFC 9111 describes an unconditional `HEAD` as a way to freshen a stored response. A range answered `206` or `416` carries its validator in `If-Range`, which yields the range or the whole representation and never a `304`. A request the origin refused is answered with every precondition ignored (§13.2.1). None of those round trips could have been shortened, so the rule stays silent on them.

**An offer no cache was allowed to accept is not one that was declined.** RFC 9111 §3 decides whether the earlier exchange left a stored response at all, and a `no-store` on either of its two messages — the response's (§5.2.2.5) or the request's (§5.2.1.5) — answers no. The `ETag` beside such a directive reached no store, so the round trip this rule calls avoidable could not have been a `304`, and the rule stays silent.

**An entry stored for one variant is not one a request for another declined.** §4's last condition on the pairing is §4.1's: the request now presented must match the stored request in every field the response's `Vary` nominates. A response served under `Vary: Accept-Encoding` to a request that asked for nothing is stored for the identity variant, and its validator could not have turned a request for gzip into a `304`, so the search reads past it. A response no cache was allowed to keep at all is no entry either, whatever validator or directive it carries: §3 also asks that the status be final and that the response advertise a freshness lifetime, or be `public` or `private`, or have a status defined as heuristically cacheable — a `412` with an `ETag` satisfies none of those, and the search reads past it.

**The entry is the newest response a cache could have kept, not simply the last one.** An exchange that left nothing stored does not replace the entry before it, and there are two ways to leave nothing: a `no-store` response was never stored, and only GET, HEAD and POST leave a stored response behind at all (RFC 9111 §4) — a stored `GET` answers a `HEAD` and nothing else. So an `OPTIONS` or a `TRACE` between the response that handed over the validator and the request that declines it is not the entry, and reading it as one reported that no validator had been offered when one had. An ordinary `200` carrying no validator is a different matter: it *was* storable, so it replaced the entry, and after it there is nothing left to condition on.

## Violations

- [conditional_missing](../violations/conditional_missing.md) — A repeat request declines a validator the server provided

## Specifications

- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): If-None-Match — a client SHOULD send it for stored responses that have entity tags when making a GET request
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): If-Modified-Since — typically used for efficient cache updates (no client obligation to send; the Last-Modified path here is a heuristic)

## Configuration

```toml
[rules.cached_validators_reused]
enabled = true
```

## Examples

### ✅ Good — the second GET names the validator the first response provided

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024

> GET /image.png HTTP/1.1
> Host: example.com
> If-None-Match: "abcdef12345"
```

### ❌ Bad — the second GET carries no precondition at all

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024

> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024

# the whole body again, where a 304 would have done
```

### ✅ Good — a HEAD after the GET: there is no content for a 304 to spare

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024

> HEAD /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024
```

### ✅ Good — a range answered 206: the validator would have gone in If-Range, which never yields a 304

```http
> GET /image.png HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< ETag: "abcdef12345"
< Content-Length: 1024

> GET /image.png HTTP/1.1
> Host: example.com
> Range: bytes=0-99

< HTTP/1.1 206 Partial Content
< Content-Range: bytes 0-99/1024
< ETag: "abcdef12345"
```
