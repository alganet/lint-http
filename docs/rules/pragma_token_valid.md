<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Pragma Token Valid

## Description

The `Pragma` header directives must follow directive syntax: a `token` optionally followed by `=token` or `="quoted-string"`.
This rule flags malformed directives, invalid token characters and empty members. The value is read as octets over the whole field section, so an octet outside visible US-ASCII in a directive name is reported as the character the production does not admit — not as a verdict about the field's encoding, which is what the reader this replaces made of it.
`Pragma` is deprecated by RFC 9111 §5.4, which no longer specifies its grammar; this validates the historical HTTP/1.0 directive syntax (originally RFC 7234 §5.4).

## Violations

- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.pragma_token_valid]
enabled = true
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Pragma: no-cache
Pragma: no-cache, foo=bar
Pragma: token="quoted,comma"
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Pragma: not a token
```

```http
GET /resource HTTP/1.1
Pragma: =abc
```
