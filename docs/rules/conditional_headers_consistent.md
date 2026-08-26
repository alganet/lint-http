<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Conditional Headers Consistent

## Description

Validate consistency and mutual exclusivity of conditional request headers. When an ETag-based conditional is present, this rule flags a redundant date-based conditional that the recipient is required to ignore (RFC 9110 §13.1.3, §13.1.4); it also ensures `If-Range` is only used with `Range` requests, disallows a weak entity-tag in `If-Range`, flags `If-Modified-Since` on methods other than GET/HEAD, and flags a repeated `If-Modified-Since`/`If-Unmodified-Since` field, whose combined value is a list of dates the recipient must ignore.

## Specifications

- [RFC 9110 §13.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1): Preconditions
- [RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5): If-Range: no If-Range without Range; no weak entity-tag in If-Range
- [RFC 9110 §13.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2): Evaluation of Preconditions (precedence rules)
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): Range (the header If-Range depends on)

## Configuration

```toml
[rules.conditional_headers_consistent]
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
