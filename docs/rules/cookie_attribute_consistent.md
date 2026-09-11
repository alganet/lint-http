<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cookie Attribute Consistent

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

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — the cookie-name/`Secure`/`HttpOnly`/`Expires` grammar this rule checks
- [RFC 6265 §5.2.2](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2): The Max-Age attribute — ignored unless it is a `-`-or-DIGIT first character with an all-DIGIT remainder
- [RFC 6265 §5.2.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3): `Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035
- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)
- [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis): `SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): SameSite cookies (SameSite=None should be Secure) — browser compatibility guidance on `SameSite` usage
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters

## Configuration

```toml
[rules.cookie_attribute_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Set-Cookie: SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None
```

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
