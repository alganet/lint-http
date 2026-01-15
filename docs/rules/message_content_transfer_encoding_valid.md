<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_content_transfer_encoding_valid

## Description

Validate the `Content-Transfer-Encoding` header value follows the canonical encodings defined by MIME: it must be a single `token` and one of `7bit`, `8bit`, `binary`, `quoted-printable`, or `base64` (case-insensitive). This header is defined by RFC 2045 and is not a list-valued header in MIME; comma-separated values are likely malformed.

## Specifications

- [RFC 2045 §6](https://www.rfc-editor.org/rfc/rfc2045#section-6) — Content-Transfer-Encoding

## Configuration

```toml
[rules.message_content_transfer_encoding_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Transfer-Encoding: base64

<response body>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Transfer-Encoding: x-custom

<response body>
```

```http
HTTP/1.1 200 OK
Content-Transfer-Encoding: base64, gzip

<response body>
```
