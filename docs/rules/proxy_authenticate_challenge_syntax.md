<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Proxy Authenticate Challenge Syntax

## Description

The `Proxy-Authenticate` response header field carries the challenges a proxy applies to a request, and RFC 9110 §11.7.1 defines it as `#challenge` — the same production `WWW-Authenticate` is a list of. This rule reads that grammar over this field: each member is an `auth-scheme` (a `token`) followed, optionally, by a `token68` or a comma-separated list of `auth-param`.

Every defect it reports is declared by `www_authenticate_challenge_syntax` too, under the same id, because the defect belongs to §11.3's production and not to the field that carried it. The two rules are separate so that a deployment can silence the grammar on one field without silencing it on the other.

**What §11.7.1 says about this field does not reach its grammar.** The section limits `Proxy-Authenticate` to the next outbound client on the response chain, which is why a `Proxy-Authenticate` on a status other than `407` is only advisory (`status_code_semantics`) and why an absent one is weaker evidence about the proxy that generated a `407`. A challenge that *is* present still has to be readable by the one recipient the field addresses, and a value the production does not derive is not.

The rule says nothing about which schemes are acceptable — that is `auth_scheme_registered`'s allowlist — nor about `Proxy-Authorization`, which carries `credentials` rather than `challenge`.

## Violations

- [auth_scheme_character_forbidden](../violations/auth_scheme_character_forbidden.md) — Authentication scheme holds a character outside token
- [challenge_member_empty](../violations/challenge_member_empty.md) — Authentication challenge list has an empty member
- [challenge_parameter_name_character_forbidden](../violations/challenge_parameter_name_character_forbidden.md) — Authentication parameter name holds a character outside token
- [challenge_parameter_name_empty](../violations/challenge_parameter_name_empty.md) — Authentication parameter has an empty name
- [challenge_parameter_value_character_forbidden](../violations/challenge_parameter_value_character_forbidden.md) — Authentication parameter value holds a character outside token
- [challenge_parameter_value_missing](../violations/challenge_parameter_value_missing.md) — Authentication parameter has no value
- [challenge_scheme_missing](../violations/challenge_scheme_missing.md) — Authentication parameter arrives before any scheme
- [challenge_token68_invalid](../violations/challenge_token68_invalid.md) — Authentication token68 is indistinguishable from a parameter
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token68_whitespace_or_control_forbidden](../violations/token68_whitespace_or_control_forbidden.md) — token68 holds whitespace or a control character

## Specifications

- [RFC 9110 §11.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1): `Proxy-Authenticate` — at least one field in each 407 a proxy generates, and the sentence limiting the field to the next outbound client on the response chain, which is all that stands behind an advisory finding on any other status
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read
- [RFC 9110 §11.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3): Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS "=" BWS ( token / quoted-string )`, and `token68`'s alphabet
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.proxy_authenticate_challenge_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="proxy"
```

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==
```

### ❌ Bad

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="unfinished
```

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: b@d realm="x"
```
