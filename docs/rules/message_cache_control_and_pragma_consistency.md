<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_cache_control_and_pragma_consistency

## Description

Flags contradictions between `Pragma` and `Cache-Control` in requests (for example, `Pragma: no-cache` together with `Cache-Control: only-if-cached`), and warns when `Pragma` appears in responses since its meaning there is unspecified. This helps avoid ambiguous or conflicting cache directives that can lead to cache-serving mistakes.

## Specifications

- [RFC 7234 §5.4](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.4) — `Pragma` and its relationship to `Cache-Control`.

## Configuration

```toml
[rules.message_cache_control_and_pragma_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Cache-Control: no-cache, max-age=0

HTTP/1.1 200 OK
Cache-Control: no-cache
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
Pragma: no-cache
Cache-Control: only-if-cached

# Contradictory directives: 'no-cache' requests should not force 'only-if-cached'
```

```http
HTTP/1.1 200 OK
Pragma: no-cache

# 'Pragma' in responses has unspecified semantics; use 'Cache-Control' instead
```

```http
HTTP/1.1 200 OK
Pragma: foo

# Any Pragma in responses is discouraged; prefer Cache-Control
```

```toml
[rules.message_cache_control_and_pragma_consistency]
enabled = true
severity = "warn"
```
