<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Digest Header Syntax

## Description

RFC 9530 obsoletes RFC 3230 and defines modern Integrity fields: `Content-Digest` (for message content), `Repr-Digest` (for representation data) and their preference counterparts `Want-Content-Digest` / `Want-Repr-Digest`. This rule validates:

- **Legacy** `Digest` / `Want-Digest` header syntax (alg=base64) and flags their use as obsoleted by RFC 9530.
- **New** RFC 9530 Integrity fields (`Content-Digest`, `Repr-Digest`) must follow the structured dictionary syntax (e.g., `sha-256=:BASE64:`) with byte sequences that decode as valid Base64.
- **Integrity preference** fields (`Want-Content-Digest`, `Want-Repr-Digest`) use algorithm=weight pairs where weight is an integer in 0..=10.
- **Deprecation**: presence of `Content-MD5` is flagged as deprecated; prefer `Content-Digest`.

## Specifications

- [RFC 9530 §2, §3, §4 - Content-Digest / Repr-Digest / Want-* fields](https://www.rfc-editor.org/rfc/rfc9530.html)

## Configuration

```toml
[rules.message_digest_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Digest: sha-256=:YWJj:
```

### ❌ Bad

```http
Content-Digest: sha-256=dGVzdA==   # missing the required ':' byte sequence delimiters
```

```http
Digest: SHA-256=not-base64!  # legacy Digest is obsoleted by RFC 9530 and will be reported
```