<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# If-None-Match ETag Syntax

## Description

`If-None-Match` headers must be either `*` or a comma-separated list of entity-tags. Entity-tags follow the grammar in RFC 9110 §7.6 and may be weak (prefix `W/`). This rule validates the basic syntax (quoting, escaping, and prohibition of control characters).

## Specifications

- [RFC 9110 §7.6 — ETag header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6)
- [RFC 9110 §7.8.4 — If-None-Match](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8.4)

## Configuration

```toml
[rules.message_if_none_match_etag_syntax]
enabled = true
severity = "warn"
```

## Examples

✅ Good

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

❌ Bad

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
