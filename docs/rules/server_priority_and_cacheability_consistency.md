<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Priority and Cacheability Consistency

## Description

When an origin server includes a `Priority` response header (RFC 9218 §5) it is expected to control the cacheability or applicability of the cached response by using cache-control related fields (for example `Cache-Control` and/or `Vary`). This rule warns when a response includes `Priority` but lacks an explicit caching directive such as `Cache-Control` or `Vary` which can lead to incorrect caching of responses that differ by request properties.

## Specifications

- [RFC 9218 §5](https://www.rfc-editor.org/rfc/rfc9218.html#section-5) — `Priority` response header guidance: "When an origin server generates the Priority response header ... the server is expected to control the cacheability ... by using header fields that control the caching behavior (e.g., Cache-Control, Vary)".
- [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) — HTTP caching and `Cache-Control`/`Vary` semantics (informative).

## Configuration

```toml
[rules.server_priority_and_cacheability_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=60
Priority: u=3

<body...>
```

### ✅ Good (Vary is present)

```http
HTTP/1.1 200 OK
Vary: Accept-Encoding
Priority: u=1

<body...>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Priority: u=2

<body...>
```

> In the bad example, the server emitted a `Priority` response header but did not provide `Cache-Control` or `Vary` to control how caches store or reuse the response.
