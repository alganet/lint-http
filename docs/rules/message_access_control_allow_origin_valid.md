<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Access-Control-Allow-Origin Syntax

## Description

This rule checks that the `Access-Control-Allow-Origin` response header is syntactically valid: it must be a single value and that value must be either `*`, `null`, or a valid serialized-origin (scheme://host[:port]). Multiple header fields or comma-separated lists are not allowed per the CORS semantics and will be flagged as violations.

## Specifications

- MDN: Access-Control-Allow-Origin — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
- CORS spec (W3C): Cross-Origin Resource Sharing (CORS) — https://www.w3.org/TR/cors/
- Fetch Standard (CORS semantics) — https://fetch.spec.whatwg.org/

## Configuration

```toml
[rules.message_access_control_allow_origin_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a, https://b
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a
Access-Control-Allow-Origin: https://b
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: example.com
```
