<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Auth Scheme Registered

## Description

Reads the HTTP authentication framework's own grammar in both directions — a server's `WWW-Authenticate` challenges and a client's `Authorization` credentials — and then asks the registry question the rule is named for. The framework half is the structure: a challenge that names no scheme, an empty list member, an `auth-scheme` carrying a character no `token` admits, an `Authorization` value that is empty or that stops after the scheme where the scheme wants credentials. The registry half is the `auth-scheme` itself, which SHOULD be an IANA-registered scheme (for example, `Basic`, `Bearer`, `Digest`); this rule measures it against an operator-configured allowlist of acceptable schemes rather than against the live registry, and flags a value not in it. What those credentials must *be* once the scheme is known belongs to the scheme's own rule.

## Specifications

- [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1): Authentication Scheme — `auth-scheme = token`, and where new schemes are registered
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read
- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half
- [RFC 9110 §16.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1): Authentication Scheme Registry
- [IANA HTTP Authentication Schemes](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml): IANA HTTP Authentication Scheme Registry
- [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html): Basic Authentication
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html): The OAuth 2.0 Authorization Framework: Bearer Token Usage

## Configuration

```toml
[rules.auth_scheme_registered]
enabled = true
allowed = ["Basic", "Bearer", "Digest"]
```

## Examples

### ✅ Good

```http
WWW-Authenticate: Basic realm="example"
Authorization: Bearer abc123
```

```http
WWW-Authenticate: Digest realm="test", nonce="abc"
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/resource", response="d41d8cd98f00b204e9800998ecf8427e"
```

### ❌ Bad

```http
WWW-Authenticate: NewScheme abc=
Authorization: X-MyAuth abc
```

```http
Authorization: Basic
```
