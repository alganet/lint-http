<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# stateful_range_request_and_caching

## Description

Caches that store partial responses (206 Partial Content) risk serving stale or
incomplete data if they later satisfy a Range request without validating that
those partial fragments still match the current representation.  To avoid this,
caches SHOULD supply an `If-Range` validator when issuing a subsequent request
that contains a `Range` header; the origin server can then return the entire
representation if the stored fragments are out of date (RFC 7233 §3.2).

This rule tracks earlier transactions for the same client and resource.  If a
previous response was 206 and included a **strong** validator (a strong
`ETag` – weak tags are ignored – or a `Last-Modified` date), a later Range
request is expected to provide `If-Range`.  The rule warns when the header is
missing or when its value does not match the validator observed in the earlier
206 response.  Note that while `If-Range` can use either kind of validator,
combining partial responses into a complete representation requires a shared
strong `ETag` (RFC 9111 §3.4).

## Specifications

- [RFC 7233 §3.2 — `If-Range` precondition to `Range` requests.](https://www.rfc-editor.org/rfc/rfc7233.html#section-3.2)
- [RFC 9111 §4.3.1 — Caches SHOULD send `If-Range` when validating partial
  responses](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1).
- [RFC 9111 §3.4 — Combining partial content requires a shared strong
  validator.](https://www.rfc-editor.org/rfc/rfc9111.html#section-3.4)

## Configuration

```toml
[rules.stateful_range_request_and_caching]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — cache includes matching validator

```http
GET /resource HTTP/1.1
Range: bytes=0-99
If-Range: "etag123"

HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000
```

(Previous transaction recorded above, allowing cache to validate before
reusing the partial body.)

### ✅ Good — validator can be a date

```http
GET /resource HTTP/1.1
Range: bytes=0-99
If-Range: Wed, 21 Oct 2015 07:28:00 GMT

HTTP/1.1 206 Partial Content
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Range: bytes 0-99/1000
```

### ❌ Bad — missing `If-Range` after earlier 206

```http
GET /resource HTTP/1.1
Range: bytes=0-99

HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000
```

### ❌ Bad — `If-Range` value does not match previous validator

```http
GET /resource HTTP/1.1
Range: bytes=0-99
If-Range: "other"

HTTP/1.1 206 Partial Content
ETag: "etag123"
Content-Range: bytes 0-99/1000
```
