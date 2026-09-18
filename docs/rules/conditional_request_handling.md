<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Conditional Request Handling

## Description

Warn when a conditional request names a validator (ETag / Last-Modified) that no response for the same resource and client ever carried. **The question is about the value, not about the response that happened to arrive last**: a tag an earlier response handed out is accounted for however many validator-less responses have followed it, and a tag no response ever carried is unaccounted for however recently some *other* tag was sent. `If-None-Match: *` and `If-Match: *` are not reported at all — `*` is an existence condition, names no validator, and is a legitimate thing for a client holding nothing to send. Also flag obvious cases where a server returns a `200` for a conditional `GET`/`HEAD` when the validator clearly matches (the server should return `304 Not Modified`).

## Violations

- [conditional_validator_missing](../violations/conditional_validator_missing.md) — A precondition names a validator this exchange never provided
- [status_304_missing](../violations/status_304_missing.md) — A false precondition is answered with 200 rather than 304

## Specifications

- [RFC 9110 §13.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1): Preconditions
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): `If-None-Match`: an origin server MUST NOT perform the method when the condition is false and MUST answer with a 304 for GET or HEAD, or a 412 otherwise
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, MUST ignore it when the value is no HTTP-date or has more than one member or the method is neither GET nor HEAD, and SHOULD answer a false condition with a 304 rather than performing the method
- [RFC 9110 §13.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2): Evaluation of Preconditions (precedence rules)
- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): Last-Modified header field

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
