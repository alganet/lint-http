<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Content-Type Present

## Description

This rule ensures that responses which likely contain a body include a `Content-Type` header. This helps downstream components and user agents interpret the response bytes correctly.

The rule considers a response to likely have a body when any of:
- `Content-Length` is present and > 0
- `Transfer-Encoding` is present
- Response status is 2xx and neither `Content-Length` nor `Transfer-Encoding` is present

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type header
- [RFC 9112 §6](https://www.rfc-editor.org/rfc/rfc9112.html#section-6): Message body length rules

## Configuration

```toml
[rules.server_content_type_present]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 123
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Length: 123
# Missing Content-Type
```
