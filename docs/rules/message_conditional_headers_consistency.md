<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Conditional Headers Consistency

## Description

Validate consistency and mutual exclusivity of conditional request headers. This rule enforces the evaluation precedence of conditional headers (ETag-based conditionals take precedence over date-based ones), ensures `If-Range` is only used with `Range` requests, and disallows weak ETags in `If-Range` when an entity-tag is used.

## Specifications

- [RFC 9110 §13.1 — Preconditions](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1)
- [RFC 9110 §13.2 — Evaluation of Preconditions (precedence rules)](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2)
- [RFC 9110 §14.2 — Range (If-Range interplay)](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2)

## Configuration

```toml
[rules.message_conditional_headers_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "abc"
```

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-99
If-Range: "abc"
```

### ❌ Bad

```http
POST /resource HTTP/1.1
Host: example.com
If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since is not meaningful for POST
```

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "abc"
If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since MUST be ignored when If-None-Match present
```

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-99
If-Range: W/"weaktag"   # If-Range must not contain a weak entity-tag
```

```http
GET /resource HTTP/1.1
Host: example.com
If-Range: "strongtag"   # missing Range header -> invalid use of If-Range
```
