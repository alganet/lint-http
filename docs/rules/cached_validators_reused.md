<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cached Validators Reused

## Description

This rule checks if the client correctly uses conditional headers (`If-None-Match`, `If-Modified-Since`, or `If-Range`) when re-requesting a resource it has previously fetched.

If a server provides validators (like `ETag` or `Last-Modified`) in a response, a well-behaved client should use them in subsequent requests for the same resource to allow the server to return a `304 Not Modified` response, saving bandwidth and processing time.

**An offer no cache was allowed to accept is not one that was declined.** RFC 9111 §3 decides whether the earlier exchange left a stored response at all, and a `no-store` on either of its two messages — the response's (§5.2.2.5) or the request's (§5.2.1.5) — answers no. The `ETag` beside such a directive reached no store, so the round trip this rule calls avoidable could not have been a `304`, and the rule stays silent.

**An entry stored for one variant is not one a request for another declined.** §4's last condition on the pairing is §4.1's: the request now presented must match the stored request in every field the response's `Vary` nominates. A response served under `Vary: Accept-Encoding` to a request that asked for nothing is stored for the identity variant, and its validator could not have turned a request for gzip into a `304`, so the search reads past it.

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

### ✅ Good Request

```http
GET /image.png HTTP/1.1
Host: example.com
```

```http
HTTP/1.1 200 OK
ETag: "abcdef12345"
Content-Length: 1024
```

```http
GET /image.png HTTP/1.1
Host: example.com
If-None-Match: "abcdef12345"
```

### ❌ Bad Request

```http
GET /image.png HTTP/1.1
Host: example.com
```

```http
HTTP/1.1 200 OK
ETag: "abcdef12345"
```

```http
GET /image.png HTTP/1.1
Host: example.com
# Missing If-None-Match header!
```
