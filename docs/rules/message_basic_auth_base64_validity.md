<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_basic_auth_base64_validity

## Description

Validate that `Authorization: Basic ...` credentials are syntactically valid Base64-encoded `user-id:password` octet sequences as defined by RFC 7617. The rule ensures the credentials decode successfully, include the required `:` separator, and that neither the user-id nor the password contains control characters.

## Specifications

- [RFC 7617 §2 — The Basic authentication scheme and the `user-pass` encoding (Base64)](https://www.rfc-editor.org/rfc/rfc7617.html#section-2)
- [RFC 4648 §4 — Base64 encoding used for `token68`](https://www.rfc-editor.org/rfc/rfc4648.html#section-4)

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_basic_auth_base64_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /protected HTTP/1.1
Host: example.com
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```

### ❌ Bad

```http
GET /protected HTTP/1.1
Host: example.com
Authorization: Basic not-base64
```

```http
GET /protected HTTP/1.1
Host: example.com
Authorization: Basic YWJj
```

(Decoded credentials missing `:` separator)
