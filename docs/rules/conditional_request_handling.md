<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Conditional Request Handling

## Description

Warn when a conditional request names a validator (ETag / Last-Modified) that no response for the same resource and client ever carried. **The question is about the value, not about the response that happened to arrive last**: a tag an earlier response handed out is accounted for however many validator-less responses have followed it, and a tag no response ever carried is unaccounted for however recently some *other* tag was sent. `If-None-Match: *` and `If-Match: *` are never reported *as an unaccounted validator* — `*` is an existence condition, names no validator, and is a legitimate thing for a client holding nothing to send.

**And flag a conditional `GET` or `HEAD` whose condition was false and was answered `200` anyway** (RFC 9110 §13.1.2 and §13.1.3 owe a `304 (Not Modified)` there). The condition is evaluated the way each section says: entity tags by the **weak** comparison §13.1.2 mandates, so `If-None-Match: W/"abc"` against an `ETag: "abc"` is a match and one `W/` added or dropped in a CDN does not make the check silent; a list is split on the commas between its members and not on the ones an `etagc` admits inside a tag; and `If-None-Match: *` is false against any `200` that carried a representation, whether or not that response also carried a validator.

**And flag a `304` that answers anything but a conditional `GET` or `HEAD`.** RFC 9110 §15.4.5 defines the status as a conditional `GET` or `HEAD` whose condition evaluated false, so a `304` to a `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `TRACE` or `CONNECT` is an answer no precondition can produce there — §13.1.2 answers a false `If-None-Match` with `412` on every other method, and §13.1.3 has `If-Modified-Since` ignored on them — and a `304` to a `GET` or `HEAD` that carried neither `If-None-Match` nor `If-Modified-Since` tells the client to reuse a stored response its request never said it holds. A method no cited document defines is declined, since it may define conditional semantics of its own.

## Violations

- [conditional_validator_missing](../violations/conditional_validator_missing.md) — A precondition names a validator this exchange never provided
- [status_304_missing](../violations/status_304_missing.md) — A false precondition is answered with 200 rather than 304
- [status_304_unsolicited](../violations/status_304_unsolicited.md) — 304 Not Modified answers a request that was not a conditional GET or HEAD
- [status_412_ambiguous](../violations/status_412_ambiguous.md) — A false precondition is answered with success, and nothing shows whether the change was already in place
- [status_412_missing](../violations/status_412_missing.md) — A false precondition on a state-changing request is answered with success rather than 412

## Specifications

- [RFC 9110 §13.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1): Preconditions
- [RFC 9110 §13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1): `If-Match`: an origin server MUST NOT perform the method when the condition is false, MAY answer 412, and MAY answer 2xx where the state-changing request appears to have already been applied
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): `If-None-Match`: an origin server MUST NOT perform the method when the condition is false and MUST answer with a 304 for GET or HEAD, or a 412 otherwise
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, MUST ignore it when the value is no HTTP-date or has more than one member or the method is neither GET nor HEAD, and SHOULD answer a false condition with a 304 rather than performing the method
- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): `If-Unmodified-Since`: the recipient MUST ignore it when an `If-Match` is present, and when the value is no HTTP-date
- [RFC 9110 §13.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2): Evaluation of Preconditions (precedence rules)
- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): Last-Modified header field
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section

## Configuration

```toml
[rules.conditional_request_handling]
enabled = true
```

## Examples

### ✅ Good — the tag the request names is the one the resource handed over

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "abc"

> GET /resource HTTP/1.1
> If-None-Match: "abc"

< 304 Not Modified  HTTP/1.1
< ETag: "abc"
```

### ❌ Bad — conditional request with no prior validator recorded

```http
> GET /resource HTTP/1.1
> If-None-Match: "abc"

< 200 OK  HTTP/1.1
< ETag: "abc"

< (body)
```

### ❌ Bad — client used conditional header without previously seeing an ETag/Last-Modified

```http
> GET /resource HTTP/1.1
> If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT

< 200 OK  HTTP/1.1
< Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad — the condition was not met, so the response owed is 304 and not a second copy

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "abc"

> GET /resource HTTP/1.1
> If-None-Match: "abc"

< 200 OK  HTTP/1.1
< ETag: "abc"
```

### ❌ Bad — one weakness indicator apart is still a match under §13.1.2's weak comparison

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: W/"abc"

> GET /resource HTTP/1.1
> If-None-Match: W/"abc"

< 200 OK  HTTP/1.1
< ETag: "abc"
```

### ❌ Bad — `*` asks whether a representation is current, and this 200 is one

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "abc"

> GET /resource HTTP/1.1
> If-None-Match: *

< 200 OK  HTTP/1.1
< Content-Type: text/html
```

### ✅ Good — an unquoted tag echoed back is no entity tag, so no condition failed; the tag is the response's defect, not the 200

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: 0x8DD2F82FA585D1E

> GET /resource HTTP/1.1
> If-None-Match: 0x8DD2F82FA585D1E

< 200 OK  HTTP/1.1
< ETag: 0x8DD2F82FA585D1E
```

### ✅ Good — the tag the PUT conditioned on was the current one, so the method was performed

```http
> GET /doc HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "v2"

> PUT /doc HTTP/1.1
> If-Match: "v2"

< 200 OK  HTTP/1.1
< ETag: "v3"
```

### ❌ Bad — the PUT conditioned on a tag the resource no longer had, and the tag moved anyway: the lost update went through

```http
> GET /doc HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "v2"

> PUT /doc HTTP/1.1
> If-Match: "v1"

< 200 OK  HTTP/1.1
< ETag: "v3"
```

### ❌ Bad — a create-only PUT on a resource that already had a representation owes a 412

```http
> GET /doc HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "v2"

> PUT /doc HTTP/1.1
> If-None-Match: *

< 200 OK  HTTP/1.1
< ETag: "v2"
```

### ❌ Bad — a false If-None-Match on a PUT is answered 412; 304 answers only a conditional GET or HEAD

```http
> GET /doc HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "v2"

> PUT /doc HTTP/1.1
> If-None-Match: "v2"

< 304 Not Modified  HTTP/1.1
< ETag: "v2"
```

### ❌ Bad — a request that stated no precondition is not told to reuse what it never said it holds

```http
> GET /resource HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "abc"

> GET /resource HTTP/1.1

< 304 Not Modified  HTTP/1.1
< ETag: "abc"
```

### ❌ Bad — the same false If-Match answered 204 with nothing to say whether the change had already been applied

```http
> GET /doc HTTP/1.1

< 200 OK  HTTP/1.1
< ETag: "v2"

> PUT /doc HTTP/1.1
> If-Match: "v1"

< 204 No Content  HTTP/1.1
```
