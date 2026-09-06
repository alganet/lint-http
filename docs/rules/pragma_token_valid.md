<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Pragma Token Valid

## Description

The `Pragma` header directives must follow directive syntax: a `token` optionally followed by `=token` or `="quoted-string"`.
This rule flags malformed directives, invalid token characters, empty members, and non-UTF8 header values.
`Pragma` is deprecated by RFC 9111 §5.4, which no longer specifies its grammar; this validates the historical HTTP/1.0 directive syntax (originally RFC 7234 §5.4).

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.pragma_token_valid]
enabled = true
severity = "warn"
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
