<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content Encoding Iana Registered

## Description

Validate `Content-Encoding` and `Accept-Encoding` header values to ensure content-coding tokens are syntactically valid and are recognised (SHOULD be IANA-registered or explicitly allowed via configuration). The rule flags unrecognised content-coding tokens and invalid token characters.

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): Content Coding
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding): IANA Content Coding registry

## Configuration

```toml
[rules.message_content_encoding_iana_registered]
enabled = true
severity = "warn"
allowed = ["aes128gcm", "br", "compress", "dcb", "dcz", "deflate", "exi", "gzip", "identity", "pack200-gzip", "x-compress", "x-gzip", "zstd"]
```

## Examples

### ✅ Good

```http
Content-Encoding: gzip
Content-Encoding: gzip, br
Accept-Encoding: gzip;q=0.8, br;q=1.0
Accept-Encoding: *
```

### ❌ Bad

```http
Content-Encoding: x-custom
Accept-Encoding: x-custom;q=0.5
Accept-Encoding: x!bad  # invalid token character '!'
```
