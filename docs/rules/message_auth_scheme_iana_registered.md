<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_auth_scheme_iana_registered

## Description

Validate authentication schemes used in `WWW-Authenticate` and `Authorization` headers. The `auth-scheme` is a `token` and SHOULD be an IANA-registered authentication scheme (for example, `Basic`, `Bearer`, `Digest`). This rule allows an operator-configured allowlist of acceptable schemes; values not present in the allowlist are flagged.

## Specifications

- [RFC 9110 §7.2.1 — WWW-Authenticate](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.1)
- [IANA HTTP Authentication Scheme Registry](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml)

## Configuration

Enable the rule and provide an `allowed` array listing acceptable scheme names (case-insensitive):

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