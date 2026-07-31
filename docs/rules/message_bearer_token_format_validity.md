<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Bearer Token Format Validity

## Description

Validate `Authorization: Bearer <token>` header values. The Bearer token MUST be present, MUST NOT contain whitespace, and MUST conform to the `token68`-like form used for credential tokens (characters from the set ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" followed by optional trailing `=` padding). Malformed Bearer tokens can lead to authentication failures or token parsing issues.

## Specifications

- [RFC 6750 §2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1): Bearer credentials — `credentials = "Bearer" 1*SP b64token`; the Authorization header form and grammar for the Bearer scheme
- [RFC 9110 §11.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2): token68 — the current auth framework's credential-token grammar, defined identically to RFC 6750's b64token; anchors the shape in a live spec (RFC 6750 references the obsolete RFC 2617). Replaces a stale RFC 7235 pointer.

## Configuration

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
