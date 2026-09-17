<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Bearer Token Syntax

## Description

Validate `Authorization: Bearer <token>` header values. The Bearer token MUST be present, MUST NOT contain whitespace, and MUST conform to the `token68`-like form used for credential tokens (characters from the set ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" followed by optional trailing `=` padding). Malformed Bearer tokens can lead to authentication failures or token parsing issues.

## Violations

- [credentials_missing](../violations/credentials_missing.md) — Credentials are absent after the scheme
- [token68_body_empty](../violations/token68_body_empty.md) — token68 is padding with no body
- [token68_character_forbidden](../violations/token68_character_forbidden.md) — token68 holds a character outside its alphabet
- [token68_padding_malformed](../violations/token68_padding_malformed.md) — token68 padding holds something other than '='
- [token68_whitespace_or_control_forbidden](../violations/token68_whitespace_or_control_forbidden.md) — token68 holds whitespace or a control character

## Specifications

- [RFC 6750 §2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1): Bearer credentials — `credentials = "Bearer" 1*SP b64token`; the Authorization header form and grammar for the Bearer scheme
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half

## Configuration

```toml
[rules.bearer_token_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Authorization: Bearer abc123
```

### ❌ Bad (whitespace in token)

```http
GET / HTTP/1.1
Authorization: Bearer a b
```

### ❌ Bad (invalid character `@`)

```http
GET / HTTP/1.1
Authorization: Bearer a@b
```
