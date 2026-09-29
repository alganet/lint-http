<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Www Authenticate Challenge Syntax

## Description

The `WWW-Authenticate` response header advertises authentication schemes that the server supports. Each challenge consists of an `auth-scheme` (a `token`) followed by optional parameters (`auth-param`) or a `token68` value.

This rule validates that each challenge:

- Begins with a valid `auth-scheme` token (no illegal characters).
- If parameters are present, each parameter is of the form `token=token` or `token="quoted-string"` and quoted-strings are well-formed.
- Token68 values are accepted as a single token-like remainder (no control characters).
- No `auth-param` name occurs twice in one challenge (RFC 9110 §11.2), the names being folded before they are compared as the same sentence requires. The count is taken inside a challenge and never across the field line, because `WWW-Authenticate = #challenge` and §11.6.1 prints two challenges each naming their own `realm` as the ordinary case.

**A repeated parameter is not reported about an `Authorization`.** §11.2's sentence counts per *challenge*, and §11.4 gives `credentials` no such unit; RFC 7616 states nothing of its own about a Digest credential naming a parameter twice. So the silence there is the documents', not this reader's.

## Violations

- [auth_param_equals_missing](../violations/auth_param_equals_missing.md) — An authentication parameter is written without its '='
- [auth_param_name_character_forbidden](../violations/auth_param_name_character_forbidden.md) — An authentication parameter name holds a character outside token
- [auth_param_name_empty](../violations/auth_param_name_empty.md) — An authentication parameter has an empty name
- [auth_param_realm_quoting_invalid](../violations/auth_param_realm_quoting_invalid.md) — A realm is written in the syntax its section refuses
- [auth_param_value_character_forbidden](../violations/auth_param_value_character_forbidden.md) — An authentication parameter value holds a character outside token
- [auth_param_value_empty](../violations/auth_param_value_empty.md) — An authentication parameter is written with no value after its '='
- [auth_scheme_character_forbidden](../violations/auth_scheme_character_forbidden.md) — Authentication scheme holds a character outside token
- [bws_forbidden](../violations/bws_forbidden.md) — Whitespace written where the grammar admits BWS
- [challenge_member_empty](../violations/challenge_member_empty.md) — Authentication challenge list has an empty member
- [challenge_parameter_duplicated](../violations/challenge_parameter_duplicated.md) — Authentication challenge names one parameter more than once
- [challenge_scheme_missing](../violations/challenge_scheme_missing.md) — Authentication parameter arrives before any scheme
- [challenge_token68_invalid](../violations/challenge_token68_invalid.md) — Authentication token68 is indistinguishable from a parameter
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token68_whitespace_or_control_forbidden](../violations/token68_whitespace_or_control_forbidden.md) — token68 holds whitespace or a control character

## Specifications

- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read
- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — `BWS` is printed where a grammar allows optional whitespace for historical reasons only, with a MUST NOT on the sender and a matching MUST on the recipient to remove it before interpreting the element
- [RFC 9110 §11.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5): Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms; the section closes by admitting one spelling of the value
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.www_authenticate_challenge_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example", error="invalid_token"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: NewScheme abcdef123=
```

### ❌ Bad

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: b@d realm="x"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="unfinished
```

### ❌ Bad (the realm derives from `auth-param`, and § 11.5 admits one spelling of it)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm=example
```

### ❌ Bad (§ 11.2 admits a parameter name once per challenge, and folds the name before comparing it)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="one", REALM="two"
```

### ✅ Good (two challenges, each naming its own realm — the count is per challenge and not per field line)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="a", Bearer realm="b"
```
