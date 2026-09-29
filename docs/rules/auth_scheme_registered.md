<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Auth Scheme Registered

## Description

The `auth-scheme` naming an HTTP authentication scheme ought to be one the IANA registry holds (for example, `Basic`, `Bearer`, `Digest`, `Negotiate`), and this rule asks that of every field § 11 writes the framework into — the challenges of a `WWW-Authenticate` or `Proxy-Authenticate`, and the credentials of an `Authorization` or `Proxy-Authorization`. The registry is the namespace for schemes in challenges and credentials, not for one hop of them, so the proxy-authentication half of the framework is asked the same question as the origin half. It measures the name against a snapshot of the registry this crate carries, and `allowed` adds the schemes a deployment knowingly uses beyond it. It used to ask a three-name list in its configuration instead, which reported `Negotiate`, `DPoP` and every other registered scheme as unregistered. **This rule reports nothing about grammar.** A scheme that is not a `token`, a challenge that does not parse, a credential missing after its scheme — each belongs to the rule that owns the field it sits in (`www_authenticate_challenge_syntax`, `authorization_credentials_valid`), and a name those rules refuse is skipped here rather than reported as unregistered, because the registry could not hold it either way.

## Violations

- [auth_scheme_unregistered](../violations/auth_scheme_unregistered.md) — An authentication scheme is not in the IANA registry

## Specifications

- [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1): Authentication Scheme — `auth-scheme = token`, and where new schemes are registered
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read
- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half
- [RFC 9110 §11.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1): `Proxy-Authenticate` — at least one field in each 407 a proxy generates, and the sentence limiting the field to the next outbound client on the response chain, which is all that stands behind an advisory finding on any other status
- [RFC 9110 §11.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.2): Proxy-Authorization — the same `credentials` addressed to the next inbound proxy instead of to the origin
- [RFC 9110 §16.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1): Authentication Scheme Registry
- [IANA HTTP Authentication Schemes](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml): IANA HTTP Authentication Scheme Registry

## Configuration

```toml
[rules.auth_scheme_registered]
enabled = true
# The IANA HTTP Authentication Scheme registry is the check, and this crate
# carries a snapshot of it. `allowed` names the schemes this deployment knowingly
# uses beyond it, and adds to the registry rather than replacing it.
allowed = []
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

### ✅ Good (registered, and on no list a deployment keeps)

```http
WWW-Authenticate: Negotiate
Authorization: Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==
```

### ❌ Bad

```http
WWW-Authenticate: NewScheme abc=
Authorization: X-MyAuth abc
```

### ❌ Bad (the proxy half of the framework, which § 11.7 writes out of the same two productions)

```http
Proxy-Authenticate: NewScheme abc=
Proxy-Authorization: X-MyAuth abc
```
