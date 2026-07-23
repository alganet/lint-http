<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# If-None-Match ETag Syntax

## Description

`If-None-Match` is either `*` or a comma-separated list of entity-tags (RFC 9110 §13.1.2). Each entity-tag follows the grammar in RFC 9110 §8.8.3 and may be weak (prefix `W/`); `If-None-Match` is evaluated with the weak comparison function, so weak tags are valid syntax here. This rule validates that field syntax (quoting, escaping, and prohibition of control characters); it does not perform the comparison.

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): ETag header field
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): If-None-Match

## Configuration

```toml
[rules.message_if_none_match_etag_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "abc123"
```

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: W/"weaktag", "strong"
```

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: *
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: abc123   # missing quotes
```

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: W/abc    # missing quoted-string after W/
```

```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "unterminated
```
