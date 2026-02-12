<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# semantic_status_code_semantics

## Description

Detects clear mismatches between HTTP response status codes and the headers/payloads that express authentication or proxy-authentication intent. Examples: a 401 response must include a `WWW-Authenticate` header; a `WWW-Authenticate` header must not appear on non-401 responses. Likewise, `Proxy-Authenticate` is specific to 407 responses. These checks help identify servers that misuse status codes or include misleading headers.

## Specifications

- [RFC 9110 §15.5.1 — 401 (Unauthorized) responses and WWW-Authenticate requirement](https://www.rfc-editor.org/rfc/rfc9110.html#name-401-unauthorized)
- [RFC 9110 §15.6.1 — 407 (Proxy Authentication Required) responses and Proxy-Authenticate](https://www.rfc-editor.org/rfc/rfc9110.html#name-407-proxy-authentication)
- [RFC 9110 §6 — Status code semantics (general)](https://www.rfc-editor.org/rfc/rfc9110.html#name-status-codes)

## Configuration

Enable the rule and set severity in your TOML config file:

```toml
[rules.semantic_status_code_semantics]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example"

{"error":"unauthorized"}
```

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="proxy"

```

❌ Bad

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
