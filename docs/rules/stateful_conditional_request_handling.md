<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Conditional Request Handling

## Description

Warn when conditional requests are used without a prior validator (ETag / Last-Modified) observed for the same resource and client. Also flag obvious cases where a server returns a `200` for a conditional `GET`/`HEAD` when the validator clearly matches (the server should return `304 Not Modified`).

## Specifications

- [RFC 9110 §13.1 — Preconditions](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1)
- [RFC 9110 §13.2 — Evaluation of Preconditions (precedence rules)](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2)
- [RFC 9110 §7.6 — ETag header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6)
- [RFC 9110 §7.7 — Last-Modified header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7)

## Configuration

```toml
[rules.stateful_conditional_request_handling]
enabled = true
severity = "warn"
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
