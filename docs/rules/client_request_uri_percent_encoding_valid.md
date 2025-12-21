<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_request_uri_percent_encoding_valid

## Description

This rule checks that percent-encodings (pct-encodings) in the request-target are well-formed: each `%` must be followed by exactly two hexadecimal digits. Malformed percent-encodings can lead to ambiguous URIs or incorrect parsing by intermediaries.

## Specifications

- RFC 3986 §2.1 — Percent-Encoding: https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1

## Configuration

```toml
[rules.client_request_uri_percent_encoding_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /path%20with%20spaces HTTP/1.1
Host: example.com
```

### ❌ Bad

```http
GET /path%2 HTTP/1.1
Host: example.com
```

```http
GET /path%GG HTTP/1.1
Host: example.com
```
