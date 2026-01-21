<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Must-Revalidate and Immutable Mismatch

## Description

This rule flags responses whose `Cache-Control` header contains both
`must-revalidate` and `immutable`. These directives have conflicting operational
implications: `must-revalidate` requires caches to revalidate once a response
becomes stale, while `immutable` signals that a response is intended to remain
unchanged and avoid revalidation during its freshness lifetime (RFC 8246).
Having both in the same response is likely a configuration mistake.

## Specifications

- [RFC 9111 §5.2.2.2 — `must-revalidate`](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2)
- [RFC 8246 — HTTP Immutable Responses (`immutable` directive)](https://www.rfc-editor.org/rfc/rfc8246.html)

## Configuration

```toml
[rules.server_must_revalidate_and_immutable_mismatch]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Cache-Control: max-age=604800, immutable
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Cache-Control: max-age=3600, immutable, must-revalidate
```
