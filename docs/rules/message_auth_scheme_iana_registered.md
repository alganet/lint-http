<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Auth Scheme Iana Registered

## Description

Validate authentication schemes used in `WWW-Authenticate` and `Authorization` headers. The `auth-scheme` is a `token` and SHOULD be an IANA-registered authentication scheme (for example, `Basic`, `Bearer`, `Digest`). This rule allows an operator-configured allowlist of acceptable schemes; values not present in the allowlist are flagged.

## Specifications

- [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1): Authentication Scheme — `auth-scheme = token`, and where new schemes are registered
- [RFC 9110 §16.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1): Authentication Scheme Registry
- [IANA HTTP Authentication Schemes](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml): IANA HTTP Authentication Scheme Registry

## Configuration

```toml
[rules.message_auth_scheme_iana_registered]
enabled = true
severity = "warn"
allowed = ["Basic", "Bearer", "Digest"]
```

## Examples

### ✅ Good

```http
WWW-Authenticate: Basic realm="example"
Authorization: Bearer abc123
```

### ❌ Bad

```http
WWW-Authenticate: NewScheme abc=
Authorization: X-MyAuth abc
```
