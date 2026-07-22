<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message If-Unmodified-Since Date Format

## Description

The `If-Unmodified-Since` request header is defined as an HTTP-date, and a sender MUST generate it in the IMF-fixdate format. This rule flags values that are not a valid IMF-fixdate — including the two obsolete formats, which a recipient must still accept but no sender may emit — or that contain non-UTF8 bytes.

## Specifications

- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): If-Unmodified-Since header

## Configuration

```toml
[rules.message_if_unmodified_since_date_format]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
If-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
GET /resource HTTP/1.1
If-Unmodified-Since: not-a-date
```

```http
GET /resource HTTP/1.1
If-Unmodified-Since: \xff
```
