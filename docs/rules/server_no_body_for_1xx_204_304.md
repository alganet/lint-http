<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server No Body For 1xx, 204, 304

## Description

Responses with status codes in the 1xx range (Informational), `204 No Content`, and `304 Not Modified` MUST NOT include a message body. This rule flags responses that contain headers which indicate a body (for example, `Transfer-Encoding: chunked` or a `Content-Length` header whose value is greater than zero).

When these statuses include a message body, intermediaries and clients can misinterpret the message framing, leading to incorrect behavior.

## Specifications
- [RFC 9110 §6.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1): Message body for status codes 1xx, 204, 304

## Configuration

```toml
[rules.server_no_body_for_1xx_204_304]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Response
```http
HTTP/1.1 204 No Content
Content-Type: text/plain
# No Content-Length or Transfer-Encoding header
```

### ❌ Bad Response (Content-Length > 0)
```http
HTTP/1.1 204 No Content
Content-Type: text/plain
Content-Length: 10
```

### ❌ Bad Response (Transfer-Encoding present)
```http
HTTP/1.1 100 Continue
Transfer-Encoding: chunked
```
