<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Length vs Transfer-Encoding

## Description

This rule flags messages (requests or responses) that include both `Content-Length` and `Transfer-Encoding` headers, which can lead to ambiguous or unsafe interpretations of message length.

## Specifications

- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length MUST NOT be sent when Transfer-Encoding is present

## Configuration

```toml
[rules.message_content_length_vs_transfer_encoding]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Message

```http
POST /submit HTTP/1.1
Host: example.com
Content-Length: 15

payload
```

### ❌ Bad Message

```http
POST /submit HTTP/1.1
Host: example.com
Content-Length: 15
Transfer-Encoding: chunked
```
