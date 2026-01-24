<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_bearer_token_format_validity

## Description

Validate `Authorization: Bearer <token>` header values. The Bearer token MUST be present, MUST NOT contain whitespace, and MUST conform to the `token68`-like form used for credential tokens (characters from the set ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" followed by optional trailing `=` padding). Malformed Bearer tokens can lead to authentication failures or token parsing issues.

## Specifications

- [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [RFC 7235 §2.1 — token68 syntax used for credentials](https://www.rfc-editor.org/rfc/rfc7235.html#section-2.1)

## Configuration

TOML snippet to enable the rule (disabled by default):

```toml
[rules.message_bearer_token_format_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Authorization: Bearer abc123
```

### ❌ Bad (whitespace in token)

```http
GET / HTTP/1.1
Authorization: Bearer a b
```

### ❌ Bad (invalid character `@`)

```http
GET / HTTP/1.1
Authorization: Bearer a@b
```
