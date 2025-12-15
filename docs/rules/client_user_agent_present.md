<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client User-Agent Present

## Description

This rule checks if the client sends a `User-Agent` header in the request.

While not strictly mandatory for all HTTP requests, the `User-Agent` header is highly recommended for identifying the client software, version, and operating system. It helps servers tailor responses and administrators debug issues.

## Specifications

- [RFC 7231 §5.5.3](https://www.rfc-editor.org/rfc/rfc7231.html#section-5.5.3): User-Agent header

## Configuration

```toml
[rules.client_user_agent_present]
enabled = true
severity = "info"
```

## Examples

### ✅ Good Request

```http
GET /api/data HTTP/1.1
Host: example.com
User-Agent: MyClient/1.0 (Linux; x64)
```

### ❌ Bad Request

```http
GET /api/data HTTP/1.1
Host: example.com
Accept: application/json
```
