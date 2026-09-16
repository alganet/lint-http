<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Auth Scheme Registered

## Description

The `auth-scheme` naming an HTTP authentication scheme SHOULD be one the IANA registry holds (for example, `Basic`, `Bearer`, `Digest`), and this rule asks that of both directions of the framework — a server's `WWW-Authenticate` challenges and a client's `Authorization` credentials. It measures the name against an operator-configured allowlist rather than against the live registry, so `allowed` is the deployment's chosen subset of acceptable schemes. **This rule reports nothing about grammar.** A scheme that is not a `token`, a challenge that does not parse, a credential missing after its scheme — each belongs to the rule that owns the field it sits in (`www_authenticate_challenge_syntax`, `authorization_credentials_valid`), and a name those rules refuse is skipped here rather than reported as unregistered, because the registry could not hold it either way.

## Specifications

- [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1): Authentication Scheme — `auth-scheme = token`, and where new schemes are registered
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read
- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half
- [RFC 9110 §16.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1): Authentication Scheme Registry
- [IANA HTTP Authentication Schemes](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml): IANA HTTP Authentication Scheme Registry

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
