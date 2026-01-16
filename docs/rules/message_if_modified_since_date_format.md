<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message If-Modified-Since Date Format

## Description

The `If-Modified-Since` request header, when present, MUST be a valid HTTP-date (IMF-fixdate). This rule flags `If-Modified-Since` header values that are not valid HTTP-date strings or contain non-UTF8 bytes.

## Specifications

- [RFC 9110 §7.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8.1): If-Modified-Since header

## Configuration

```toml
[rules.message_if_modified_since_date_format]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
GET /resource HTTP/1.1
If-Modified-Since: not-a-date
```

```http
GET /resource HTTP/1.1
If-Modified-Since: \xff
```