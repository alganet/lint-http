<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# message_www_authenticate_challenge_syntax

## Description

The `WWW-Authenticate` response header advertises authentication schemes that the server supports. Each challenge consists of an `auth-scheme` (a `token`) followed by optional parameters (`auth-param`) or a `token68` value.

This rule validates that each challenge:

- Begins with a valid `auth-scheme` token (no illegal characters).
- If parameters are present, each parameter is of the form `token=token` or `token="quoted-string"` and quoted-strings are well-formed.
- Token68 values are accepted as a single token-like remainder (no control characters).

## Specifications

- [RFC 9110 §7.2.1 — WWW-Authenticate](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.1)
- [RFC 7235 §2.1 — Challenge and `token68`](https://www.rfc-editor.org/rfc/rfc7235.html#section-2.1)

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_www_authenticate_challenge_syntax]
enabled = true
severity = "warn"
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
