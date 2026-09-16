<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Conditional Request Handling

## Description

Warn when conditional requests are used without a prior validator (ETag / Last-Modified) observed for the same resource and client. Also flag obvious cases where a server returns a `200` for a conditional `GET`/`HEAD` when the validator clearly matches (the server should return `304 Not Modified`).

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

### ✅ Good

```http
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
