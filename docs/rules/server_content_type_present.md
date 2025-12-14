<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Content-Type Present

## Description
This rule ensures that responses which likely contain a body include a `Content-Type` header. This helps downstream components and user agents interpret the response bytes correctly.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type header
- [RFC 7230 §3.3](https://www.rfc-editor.org/rfc/rfc7230.html#section-3.3): Content-Length / Transfer-Encoding message length rules
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html): HTTP status semantics (1xx, 204, 304 do not carry a body)
## Behaviour
The rule currently considers a response to likely have a body when any of:
- `Content-Length` is present and > 0
- `Transfer-Encoding` is present
- Response status is 2xx and neither `Content-Length` nor `Transfer-Encoding` is present

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

## Configuration
Enable the rule in your TOML config:

```toml
[rules.server_content_type_present]
enabled = true
```
