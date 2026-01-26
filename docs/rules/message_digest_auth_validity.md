<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_digest_auth_validity

## Description

Digest `Authorization` credentials must include the required auth-params and use syntactically valid tokens or quoted-strings. This rule checks `Authorization: Digest ...` request headers for presence of required fields and basic syntactic validity (e.g., `username`, `realm`, `nonce`, `uri`, `response`).

Servers and clients relying on Digest authentication may behave incorrectly when required parameters are missing or malformed.

## Specifications

- [RFC 7616 §3.2.2 — HTTP Digest Access Authentication](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.2.2)

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_digest_auth_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good
```http
GET /protected HTTP/1.1
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/protected", response="d41d8cd98f00b204e9800998ecf8427e"
```

### ❌ Bad (missing response)
```http
GET /protected HTTP/1.1
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/protected"
```

### ❌ Bad (invalid token characters)
```http
GET /protected HTTP/1.1
Authorization: Digest username=Mu!fasa, realm="test", nonce="abc", uri="/protected", response="d41d8c"
```
