<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Header Presence for CORS Preflight and Cross-Origin Absolute-form Requests

## Description

This rule enforces that requests which indicate cross-origin intent include an `Origin` header. In particular:

- CORS preflight requests (an `OPTIONS` request with `Access-Control-Request-Method` or `Access-Control-Request-Headers`) MUST include an `Origin` header.
- If a client uses an absolute-form request-target whose origin differs from the `Host` header, the request is treated as cross-origin and SHOULD include an `Origin` header.

The rule validates that `Origin` is present where required and that its value is syntactically plausible (a serialized origin such as `https://example.com` or the literal `null`). This rule applies to client requests (RuleScope::Client).

## Specifications

- RFC 6454 — The Web Origin Concept — https://datatracker.ietf.org/doc/html/rfc6454
- CORS / Fetch: Origin header semantics — https://fetch.spec.whatwg.org/#origin-header
- MDN: Origin — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin

## Configuration

```toml
[rules.client_request_origin_header_present_for_cors]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (preflight)

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Origin: https://example.org
Access-Control-Request-Method: POST
```

### ✅ Good (absolute-form same origin)

```http
GET http://example.com/resource HTTP/1.1
Host: example.com
```

### ❌ Bad (preflight missing Origin)

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Access-Control-Request-Method: POST
```

### ❌ Bad (absolute-form to other origin missing Origin)

```http
GET http://other.example/resource HTTP/1.1
Host: example.com
```
