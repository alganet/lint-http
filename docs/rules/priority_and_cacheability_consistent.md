<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Priority and Cacheability Consistency

## Description

When an origin server includes a `Priority` response header (RFC 9218 §5) it is expected to control the cacheability or applicability of the cached response by using cache-control related fields (for example `Cache-Control` and/or `Vary`). This rule warns when a response includes `Priority` but lacks an explicit caching directive such as `Cache-Control` or `Vary` which can lead to incorrect caching of responses that differ by request properties.

## Violations

- [priority_cacheability_missing](../violations/priority_cacheability_missing.md) — A Priority response says nothing about caching

## Specifications

- [RFC 9218 §5](https://www.rfc-editor.org/rfc/rfc9218.html#section-5): The `Priority` response header field — an end-to-end signal a server may generate from properties of the request, and the expectation that a server doing so also controls the cacheability of what it sends
- [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html): HTTP caching and `Cache-Control`/`Vary` semantics (informative)

## Configuration

```toml
[rules.priority_and_cacheability_consistent]
enabled = true
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
