<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Target No Fragment

## Description

The request-target (URI) sent in the request line MUST NOT include a fragment identifier (`#`). This applies to all forms of request-target, including `origin-form` and `absolute-form`.

Fragment identifiers are intended for client-side use only (e.g., to scroll to a specific part of a page) and have no meaning to the server. Sending them in the request line is a protocol violation.

## Specifications

- [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5): Fragment
- [RFC 9112 §2.7](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.7): Request-Target

## Configuration

```toml
[rules.client_request_target_no_fragment]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Request
```http
GET /index.html HTTP/1.1
Host: example.com
```

### ❌ Bad Request (Fragment in origin-form)
```http
GET /index.html#section1 HTTP/1.1
Host: example.com
```

### ❌ Bad Request (Fragment in absolute-form)
```http
GET http://example.com/index.html#section1 HTTP/1.1
```
