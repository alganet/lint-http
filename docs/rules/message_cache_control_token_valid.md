<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_cache_control_token_valid

## Description

Validate `Cache-Control` directive names and unquoted values follow the `token` grammar. Values that are quoted-strings are validated as quoted strings. Empty header values and empty directive members are flagged as violations.

## Specifications

- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2) — Cache-Control directives and general directive syntax

## Configuration

```toml
[rules.message_cache_control_token_valid]
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