<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# message_cookie_attribute_consistency

## Description

Validate `Set-Cookie` attributes for syntactic correctness and common security consistency rules. This rule parses `Set-Cookie` header values and flags:

- Invalid cookie-name tokens.
- Malformed attributes (e.g., `Max-Age` non-numeric, `Expires` not an HTTP-date).
- `Path` values that don't start with `/`.
- `Domain` values that are empty or contain spaces.
- `SameSite` values other than `Strict`, `Lax`, or `None`.
- `SameSite=None` cookies that are not marked `Secure` (browser behaviour / compatibility requirement).
- `Secure` and `HttpOnly` attributes that incorrectly include a value (they must be flags).

## Specifications

- [RFC 6265 §5.2.2 — Set-Cookie header attributes and semantics](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2)
- [MDN — SameSite cookies (SameSite=None should be Secure)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) — browser compatibility guidance on `SameSite` usage.
- [RFC 9110 §7.1.1 — HTTP-date (IMF-fixdate)](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1.1) — used for the `Expires` attribute.

## Configuration

TOML example to enable the rule:

```toml
[rules.message_cookie_attribute_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Set-Cookie: SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None
```

### ✅ Good

```http
Set-Cookie: sid=abcd; Path=/login; HttpOnly
```

### ❌ Bad — SameSite=None must be Secure

```http
Set-Cookie: id=1; SameSite=None
```

### ❌ Bad — Max-Age must be numeric

```http
Set-Cookie: SID=1; Max-Age=abc
```

### ❌ Bad — Expires must be a valid HTTP-date

```http
Set-Cookie: SID=1; Expires=NotADate
```
