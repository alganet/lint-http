<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_authorization_credentials_present

## Description

The `Authorization` request header field MUST include an authentication scheme followed by credentials. This rule flags requests where the header is empty, contains an invalid auth-scheme token, or is missing credentials after the scheme. Ensuring credentials are present helps detect malformed or truncated authorization attempts.

## Specifications

- [RFC 9110 §7.6.2 — Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2)
- [RFC 7617 — Basic Authentication](https://www.rfc-editor.org/rfc/rfc7617.html)
- [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)

## Configuration

```toml
[rules.message_authorization_credentials_present]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Bearer abc123
```

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Digest username="Mufasa", realm="test"
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Basic
```

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: B@sic abc
```
