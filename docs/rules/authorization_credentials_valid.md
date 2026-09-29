<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Authorization Credentials

## Description

The `Authorization` and `Proxy-Authorization` request header fields both carry credentials: an authentication scheme, then the authentication information that scheme defines. § 11.6.2 and § 11.7.2 write the same production for them and differ only in which hop consumes the value, so this rule reads that framework structure in either and names the field it read. It reports a field that is empty, one whose `auth-scheme` carries a character no `token` admits, one that stops after the scheme where the scheme wants credentials, and a control octet in the credentials themselves — and then it reads what § 11.4 writes after the scheme, `[ 1*SP ( token68 / #auth-param ) ]`, which § 11.3 writes identically for a challenge and one reader answers for both. A single `token68` is accepted whatever it holds, because a bare word is derived by that alternative and by an `auth-param` whose value was left off, and on this side of the framework nothing is missing from it; the parameters are read in full. **A word closing on one `=` is the same ambiguity a second time and is settled the same way.** `token68` ends in `*"="`, so `Basic dXNlcjpwYXNzMTI=` is a padded credential and is equally an `auth-param` written with its `=` and no value — and RFC 7617 § 2 and RFC 6750 § 2.1 both write a `token68` for this side, so it is accepted here and reported in a challenge, where those documents write parameters instead. `Digest` is the one scheme that decides without a direction: RFC 7616 gives it no `token68` form at all. Every field line is read, because a sender wrote each — that a request carries more than one line of either field is `singleton_fields_not_repeated`'s finding. What the credentials must *be* once the scheme is known belongs to the scheme's own rule; whether the scheme is one the deployment accepts belongs to `auth_scheme_registered`.

## Violations

- [auth_param_equals_missing](../violations/auth_param_equals_missing.md) — An authentication parameter is written without its '='
- [auth_param_name_character_forbidden](../violations/auth_param_name_character_forbidden.md) — An authentication parameter name holds a character outside token
- [auth_param_name_empty](../violations/auth_param_name_empty.md) — An authentication parameter has an empty name
- [auth_param_realm_quoting_invalid](../violations/auth_param_realm_quoting_invalid.md) — A realm is written in the syntax its section refuses
- [auth_param_value_character_forbidden](../violations/auth_param_value_character_forbidden.md) — An authentication parameter value holds a character outside token
- [auth_param_value_empty](../violations/auth_param_value_empty.md) — An authentication parameter is written with no value after its '='
- [auth_scheme_character_forbidden](../violations/auth_scheme_character_forbidden.md) — Authentication scheme holds a character outside token
- [bws_forbidden](../violations/bws_forbidden.md) — Whitespace written where the grammar admits BWS
- [credentials_control_character_forbidden](../violations/credentials_control_character_forbidden.md) — Credentials hold a control character
- [credentials_empty](../violations/credentials_empty.md) — Credentials are empty
- [credentials_missing](../violations/credentials_missing.md) — Credentials are absent after the scheme
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE

## Specifications

- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half
- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — `BWS` is printed where a grammar allows optional whitespace for historical reasons only, with a MUST NOT on the sender and a matching MUST on the recipient to remove it before interpreting the element
- [RFC 9110 §11.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5): Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms; the section closes by admitting one spelling of the value
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
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

### ✅ Good (a `token68` closes with `*"="`, so base64 padding is inside the production)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Basic dXNlcjpwYXNzMTI=
```

### ✅ Good (RFC 6750 §2.1 writes the same alternative for this scheme)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Bearer mF_9.B5f-4.1JqM=
```

### ✅ Good

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

### ❌ Bad (the other field § 11 writes as `credentials`)

```http
GET /resource HTTP/1.1
Host: example.com
Proxy-Authorization: Basic
```

### ❌ Bad (an `#auth-param` member with nothing in it)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom realm="x", , qop="auth"
```

### ❌ Bad (a value where the name goes)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom ="x"
```

### ❌ Bad (an octet no `token` admits, in the name)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom re@alm="x"
```

### ❌ Bad (a parameter written without its `=`)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom realm="x", qop
```

### ❌ Bad (a parameter written with nothing after its `=`)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom realm="x", qop=
```

### ❌ Bad (an octet no `token` admits, in an unquoted value)

```http
GET /resource HTTP/1.1
Host: example.com
Authorization: Custom realm=a@b
```
