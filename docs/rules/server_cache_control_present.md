<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Cache-Control Present

## Description

This rule checks if `200 OK` responses include a `Cache-Control` header.

The `Cache-Control` header is the primary mechanism for defining the caching policies of a resource. Even if a resource should not be cached, it is best practice to explicitly state this (e.g., `Cache-Control: no-store`) rather than relying on default browser behaviors or heuristic caching.

## Specifications

- [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2): Calculating Heuristic Freshness — without an explicit expiration time a cache MAY guess one, which is what this rule asks the origin to avoid
- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control — the header whose absence the rule reports

## Configuration

```toml
[rules.server_cache_control_present]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
# Missing Cache-Control header
```
