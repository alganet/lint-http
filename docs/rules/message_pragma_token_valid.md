<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Pragma Token Valid

## Description

The `Pragma` header directives must follow directive syntax: a `token` optionally followed by `=token` or `="quoted-string"`.
This rule flags malformed directives, invalid token characters, empty members, and non-UTF8 header values.

## Specifications

- [RFC 9110 §8.2 — Pragma](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.2)

## Configuration

```toml
[rules.message_pragma_token_valid]
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
