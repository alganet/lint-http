<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Semantic Status Code Semantics

## Description

Detects clear mismatches between HTTP response status codes and the headers/payloads that express authentication or proxy-authentication intent. Examples: a 401 response must include a `WWW-Authenticate` header; a `WWW-Authenticate` header must not appear on non-401 responses. Likewise, `Proxy-Authenticate` is specific to 407 responses. These checks help identify servers that misuse status codes or include misleading headers.

## Specifications

- [RFC 9110 §15.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.1): 401 (Unauthorized) responses and WWW-Authenticate requirement
- [RFC 9110 §15.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.1): 407 (Proxy Authentication Required) responses and Proxy-Authenticate
- [RFC 9110 §6](https://www.rfc-editor.org/rfc/rfc9110.html#section-6): Status code semantics (general)

## Configuration

```toml
[rules.semantic_status_code_semantics]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example"

{"error":"unauthorized"}
```

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="proxy"
```

### ❌ Bad

```http
HTTP/1.1 200 OK
WWW-Authenticate: Basic realm="example"

{"ok":true}
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"unauthorized"}
```
