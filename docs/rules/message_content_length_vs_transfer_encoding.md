<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Length vs Transfer-Encoding

## Description
This rule flags messages (requests or responses) that include both `Content-Length` and `Transfer-Encoding` headers, which can lead to ambiguous or unsafe interpretations of message length.

## Specifications

- [RFC 7230 §3.3](https://www.rfc-editor.org/rfc/rfc7230.html#section-3.3): Content-Length MUST NOT be sent when Transfer-Encoding is present
## Examples

### ✅ Good Request
```http
POST /submit HTTP/1.1
Host: example.com
Content-Length: 15

payload
```

### ❌ Bad Request
```http
POST /submit HTTP/1.1
Host: example.com
Content-Length: 15
Transfer-Encoding: chunked
```

## Configuration
Enable the rule in your TOML config:

```toml
[rules.message_content_length_vs_transfer_encoding]
enabled = true
```
