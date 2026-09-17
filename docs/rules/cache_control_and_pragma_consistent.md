<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Control And Pragma Consistent

## Description

Flags contradictions between `Pragma` and `Cache-Control` in requests (for example, `Pragma: no-cache` together with `Cache-Control: only-if-cached`), and warns when `Pragma` appears in responses since its meaning there is unspecified. This helps avoid ambiguous or conflicting cache directives that can lead to cache-serving mistakes.

## Violations

- [pragma_conflicting](../violations/pragma_conflicting.md) — A request asks for no-cache in the field its Cache-Control overrides
- [pragma_obsolete](../violations/pragma_obsolete.md) — A response carries a field this specification deprecates

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all

## Configuration

```toml
[rules.cache_control_and_pragma_consistent]
enabled = true
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
