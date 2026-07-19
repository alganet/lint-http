<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Structured Headers Validity

## Description

Validate that specified header fields are valid RFC 8941 Structured Field values (Item, List, or Dictionary). This rule checks for syntactic correctness (tokens, quoted-strings, numbers, booleans, byte-sequences, and simple parameters) and reports malformed header values. It is intentionally conservative and focuses on common syntactic errors.

## Specifications

- [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html): Structured Field Values for HTTP
- [RFC 9651 §3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3): Items, Lists, Dictionaries

## Configuration

```toml
[rules.message_structured_headers_validity]
enabled = true
severity = "warn"
headers = ["Priority", "Permissions-Policy"]
```

## Examples

### ✅ Good

```http
Priority: u=3, i
Permissions-Policy: interest-cohort=()
Accept-Patch: application/json-patch+json
Content-Digest: sha-256=:BASE64=
```

### ❌ Bad

```http
Priority: u=INVALID  # invalid token (structured field tokens cannot start with uppercase)
Permissions-Policy: bad(token)  # invalid token characters: '(' and ')'
Accept-Patch: "unterminated  # unbalanced quoted-string
Content-Digest: sha-256=:???=  # invalid byte-sequence
```
