<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Vary and Cache Consistency

## Description

When a response includes `Vary: *`, caches cannot select that stored response for subsequent requests (a `Vary: *` always fails to match). If the same response advertises explicit cacheability directives (such as `Cache-Control: max-age`/`s-maxage` or `public`), those directives are likely ineffective for reuse by caches. This rule flags cases where `Vary: *` and explicit cacheability directives are both present.

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field (a `Vary: *` never matches)
- [RFC 9111 §3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3): Storing Responses in Caches (cacheability requirements)

## Configuration

```toml
[rules.vary_and_cache_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Vary: Accept-Encoding
Cache-Control: max-age=3600

<response body>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Vary: *
Cache-Control: max-age=3600

<response body>
```
