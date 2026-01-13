<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Referer Header URI Valid

## Description

This rule checks that the `Referer` request header, when present, is a syntactically valid URI-reference per the HTTP specification. Malformed `Referer` values can break referrer-based logic and leak incorrect information to servers.

## Specifications

- [RFC 9110 §7.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#name-referer)
- [RFC 3986 §4](https://www.rfc-editor.org/rfc/rfc3986.html#section-4) — URI-reference syntax and percent-encoding

## Configuration

```toml
[rules.message_referer_uri_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (absolute URI)

```http
GET / HTTP/1.1
Referer: https://example.com/path
```

### ✅ Good (relative URI-reference)

```http
GET / HTTP/1.1
Referer: /relative/path
```

### ❌ Bad (invalid percent-encoding)

```http
GET / HTTP/1.1
Referer: /bad%2Gencoding
```

### ❌ Bad (contains whitespace)

```http
GET / HTTP/1.1
Referer: https://example.com/ bad
```
