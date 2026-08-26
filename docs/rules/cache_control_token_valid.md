<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Control Token Valid

## Description

Validate `Cache-Control` directive names and unquoted values follow the `token` grammar. Values that are quoted-strings are validated as quoted strings. An empty directive member within the list (for example a stray or trailing comma) is flagged; an entirely empty header value is not, because `Cache-Control` is a comma-separated list and an empty value is a legal zero-element list.

## Specifications

- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control directives and general directive syntax

## Configuration

```toml
[rules.cache_control_token_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Cache-Control: max-age=3600
Cache-Control: no-cache
Cache-Control: private="Set-Cookie, X-Foo"
Cache-Control: public, max-age=60
```

### ❌ Bad

```http
Cache-Control: =abc
Cache-Control: ma x-age=1
Cache-Control: private=Set Cookie
Cache-Control: private=bad@val
```
