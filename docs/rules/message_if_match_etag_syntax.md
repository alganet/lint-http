<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# If-Match ETag Syntax

## Description

`If-Match` header must be either `*` or a comma-separated list of entity-tags. Entity-tags follow the grammar in RFC 9110 §7.6 and may be weak (prefix `W/`). This rule validates the basic syntax (quoting, escaping, and prohibition of control characters).

## Specifications

- [RFC 9110 §7.6 — ETag header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6)
- [RFC 9110 §7.8.3 — If-Match](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8.3)

## Configuration

```toml
[rules.message_if_match_etag_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: "abc123"
```

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: W/"weaktag", "strong"
```

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: *
```

### ❌ Bad

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: abc123   # missing quotes
```

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: W/abc    # missing quoted-string after W/
```

```http
PUT /resource HTTP/1.1
Host: example.com
If-Match: "unterminated
```