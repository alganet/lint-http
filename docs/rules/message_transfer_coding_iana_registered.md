<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Transfer Coding Iana Registered

## Description

Validate `Transfer-Encoding` and `TE` header values to ensure transfer-coding tokens are syntactically valid and are recognised (SHOULD be IANA-registered or explicitly allowed via configuration). The `TE` header's special value `trailers` is accepted.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer Coding
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE header
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#transfer-coding): IANA Transfer Coding registry

## Configuration

```toml
[rules.message_transfer_coding_iana_registered]
enabled = true
severity = "warn"
allowed = ["chunked", "gzip", "deflate"]
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

0
```

### ✅ Good (TE request)

```http
GET / HTTP/1.1
Host: example.com
TE: trailers
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Transfer-Encoding: x-custom
```
