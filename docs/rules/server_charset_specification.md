<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Charset Specification

## Description

This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter.

Specifying the character encoding is crucial for security and correct rendering. If the charset is not explicitly defined, browsers may attempt to guess the encoding (MIME sniffing), which can lead to Cross-Site Scripting (XSS) vulnerabilities or incorrect display of characters.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type header
- [MDN: Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)

## Configuration

```toml
[rules.server_charset_specification]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: text/html
# Missing charset parameter
```
