<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Last-Modified RFC 1123 Format

## Description

Verifies that the `Last-Modified` header (when present) uses the IMF-fixdate format (a.k.a. RFC 1123 date) as required by HTTP date formatting rules.

## Specifications

- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats

## Configuration

```toml
[rules.server_last_modified_rfc1123_format]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Type: text/plain

Hello
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Last-Modified: 2015-10-21T07:28:00Z
Content-Type: text/plain

Hello
```
