<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Immutable Requires Freshness

## Description

This rule flags responses whose `Cache-Control` header pairs `immutable` with a directive that leaves the response no freshness lifetime — `no-store`, `no-cache`, `max-age=0`, or `s-maxage=0`. Per RFC 8246, `immutable` only applies during a stored response's freshness lifetime: it tells clients the representation will not change while the response is fresh, and asks them not to revalidate during that window. A response that can never be fresh has no such window, so `immutable` has nothing to act on, and one of the two directives is a mistake.

Note: `immutable` together with `must-revalidate` is **not** flagged. Those directives govern disjoint windows — `immutable` applies while the response is fresh, `must-revalidate` binds once it has gone stale — and RFC 8246 says stale responses "SHOULD be revalidated as they normally would be in the absence of the immutable extension". `Cache-Control: max-age=3600, immutable, must-revalidate` is coherent. An earlier version of this rule (`server_must_revalidate_and_immutable_mismatch`) reported that pairing as an error. It was wrong: no sentence in RFC 9111 or RFC 8246 supported it.

## Specifications

- [RFC 8246 §2](https://www.rfc-editor.org/rfc/rfc8246.html#section-2): The `immutable` Cache-Control extension — applies only during the freshness lifetime
- [RFC 9111 §5.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2): Response directives: `no-store`, `no-cache`, `max-age`, `s-maxage`

## Configuration

```toml
[rules.server_immutable_requires_freshness]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Cache-Control: max-age=604800, immutable
```

### ✅ Good Response (immutable while fresh, revalidated once stale)

```http
HTTP/1.1 200 OK
Cache-Control: max-age=3600, immutable, must-revalidate
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Cache-Control: no-cache, immutable
```

```http
HTTP/1.1 200 OK
Cache-Control: max-age=0, immutable
```
