<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_content_encoding_and_type_consistency

## Description

Validate `Content-Encoding` header members for common correctness issues: members must be valid `token`s, duplicate codings are likely a mistake and are flagged, and responses that must not carry a message body (1xx, 204, 304) MUST NOT include a `Content-Encoding` header.

## Specifications

- [RFC 9110 §5.3 — Content Coding](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3)
- [RFC 9110 §6.3 — Message Body and status codes (1xx, 204, 304)](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.3)

## Configuration

TOML snippet to enable the rule (disabled by default):

```toml
[rules.message_content_encoding_and_type_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, br
Content-Type: application/json; charset=utf-8

...compressed JSON body...
```

### ❌ Bad (duplicate coding)

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, gzip
Content-Type: application/json

...compressed JSON body...
```

### ❌ Bad (Content-Encoding on no-body response)

```http
HTTP/1.1 204 No Content
Content-Encoding: gzip
```
