<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A response coded from Accept-Encoding names it in Vary

## Description

Reports a cacheable response whose content coding was chosen from the request's `Accept-Encoding` and whose `Vary` does not name that field.

**The coding is the selection, and the response says so.** A server answering `Accept-Encoding: gzip, br` with `Content-Encoding: br` has tailored the content to a preference the request expressed — the case RFC 9110 §12.5.5 has in mind when it says an origin *"SHOULD generate a Vary header field on a cacheable response when it wishes that response to be selectively reused"*. Without it, a cache compares nothing about the next request's `Accept-Encoding` (RFC 9111 §4.1) and hands the `br` body to a client that cannot decode it.

**When it is not reported.** The SHOULD is conditional, and each condition the wire shows is read:

- the response has to be one a cache could keep at all (RFC 9111 §3) — a `GET`, a final status, no `no-store`, and some licence to store it;
- the request has to have carried a non-empty `Accept-Encoding`: a request without one accepts any coding (§12.5.3), so a coded answer to it selected nothing;
- the response must not already limit reuse. §12.5.5 lets `Vary` be elided *"particularly when reuse is already limited by cache response directives"*, so an unqualified `no-cache`, a `private`, or a `max-age=0` with no `s-maxage` is the origin having made that choice.

`Vary: *` satisfies it — no cache reuses such a response under any coding — and so does `Accept-Encoding` on any `Vary` field line, in any case.

**Not this rule's.** Whether the coding is registered, or one the request accepted, is `content_encoding_registered`'s; a coded response whose earlier sibling for the same resource shared its strong `ETag` is `etag_and_content_encoding_consistent`'s.

## Violations

- [vary_accept_encoding_missing](../violations/vary_accept_encoding_missing.md) — A response coded from Accept-Encoding does not name it in Vary

## Specifications

- [RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5): Vary — an origin SHOULD send it on a cacheable response whose content was tailored to the request's preferences, and might elide it where reuse is already limited by cache directives
- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a cache matches a later request only on the fields the stored response nominated, so a field left out is one a cache never compares

## Configuration

```toml
[rules.vary_and_content_encoding_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
GET /app.js HTTP/1.1
Host: example.com
Accept-Encoding: gzip, br

HTTP/1.1 200 OK
Content-Encoding: br
Vary: Accept-Encoding
Cache-Control: max-age=3600
```

### ✅ Good — reuse already limited by the response's own directives

```http
GET /app.js HTTP/1.1
Host: example.com
Accept-Encoding: gzip, br

HTTP/1.1 200 OK
Content-Encoding: br
Cache-Control: private, max-age=3600
```

### ❌ Bad

```http
GET /app.js HTTP/1.1
Host: example.com
Accept-Encoding: gzip, br

HTTP/1.1 200 OK
Content-Encoding: br
Cache-Control: public, max-age=3600
```
