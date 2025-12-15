<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Length Non-negative

## Description

When present, the `Content-Length` header field value MUST be a non-negative decimal integer (no sign characters). This rule flags `Content-Length` header values that are empty, contain non-digit characters, or include explicit signs (e.g., `-1`, `+1`, `1.5`, `abc`).

Improper `Content-Length` values can cause message framing errors and lead to truncated or misinterpreted message bodies.

## Specifications
- [RFC 7230 §3.3](https://www.rfc-editor.org/rfc/rfc7230.html#section-3.3): Message Body and Content-Length

## Configuration

```toml
[rules.message_content_length_non_negative]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good
```http
Content-Length: 0
Content-Length: 10
Content-Length:  20  
```

### ❌ Bad
```http
Content-Length: -1
Content-Length: +1
Content-Length: 1.5
Content-Length: abc
Content-Length:
```