<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Authorization Credentials

## Description

The `Authorization` request header field carries credentials: an authentication scheme, then the authentication information that scheme defines. This rule reads that framework structure and reports a field that is empty, one whose `auth-scheme` carries a character no `token` admits, one that stops after the scheme where the scheme wants credentials, and a control octet in the credentials themselves. Every field line is read, because a sender wrote each — that a request carries more than one `Authorization` line is `singleton_fields_not_repeated`'s finding. What the credentials must *be* once the scheme is known belongs to the scheme's own rule; whether the scheme is one the deployment accepts belongs to `auth_scheme_registered`.

## Violations

- [auth_scheme_character_forbidden](../violations/auth_scheme_character_forbidden.md) — Authentication scheme holds a character outside token
- [credentials_control_character_forbidden](../violations/credentials_control_character_forbidden.md) — Credentials hold a control character
- [credentials_empty](../violations/credentials_empty.md) — Credentials are empty
- [credentials_missing](../violations/credentials_missing.md) — Credentials are absent after the scheme

## Specifications

- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half
- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html): Basic Authentication
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html): The OAuth 2.0 Authorization Framework: Bearer Token Usage

## Configuration

```toml
[rules.authorization_credentials_valid]
enabled = true
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
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/resource", response="d41d8cd98f00b204e9800998ecf8427e"
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
