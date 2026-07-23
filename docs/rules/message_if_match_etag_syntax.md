<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# If-Match ETag Syntax

## Description

`If-Match` is either `*` or a comma-separated list of entity-tags (RFC 9110 §13.1.1). Each entity-tag follows the grammar in RFC 9110 §8.8.3 and may be weak (prefix `W/`); a weak tag is valid syntax here even though `If-Match` itself is evaluated with the strong comparison function. This rule validates that field syntax (quoting, escaping, and prohibition of control characters); it does not flag weak tags.

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): ETag header field
- [RFC 9110 §13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1): If-Match

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
