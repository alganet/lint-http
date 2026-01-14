<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_range_and_content_range_consistency

## Description

Validate the semantics and syntax of `Range` (request) and `Content-Range` (response) interactions.
This rule enforces that 206 (Partial Content) responses include a valid `Content-Range` describing the enclosed byte range, that 416 (Range Not Satisfiable) responses include an unsatisfiable `Content-Range` (`bytes */<length>`), and that `Content-Length` (when present) matches the indicated range length.

## Specifications

- [RFC 7233 §4.1 — 206 Partial Content: single-part 206 responses MUST include a `Content-Range` header describing the enclosed range.](https://www.rfc-editor.org/rfc/rfc7233.html#section-4.1)
- [RFC 7233 §4.2 — Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges.](https://www.rfc-editor.org/rfc/rfc7233.html#section-4.2)
- [RFC 7233 §4.4 — 416 Range Not Satisfiable: server SHOULD include `Content-Range: bytes */<complete-length>` in 416 responses.](https://www.rfc-editor.org/rfc/rfc7233.html#section-4.4)

## Configuration

```toml
[rules.message_range_and_content_range_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-499

HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Content-Length: 500
Content-Type: application/octet-stream

...500 bytes...
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-499

HTTP/1.1 206 Partial Content
Content-Length: 500

...500 bytes but missing Content-Range in headers...
```

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 206 Partial Content
Content-Range: bytes 0-1/10

# 206 must not be sent if the request did not include a Range header
```

```http
HTTP/1.1 416 Range Not Satisfiable
Content-Range: bytes 0-1/10

# 416 must use a "*/length" unsatisfied-range form
```
