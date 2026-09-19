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

## Violations

- [cookie_domain_empty](../violations/cookie_domain_empty.md) — Set-Cookie Domain attribute is empty
- [cookie_domain_missing](../violations/cookie_domain_missing.md) — Set-Cookie Domain attribute carries no value
- [cookie_expires_malformed](../violations/cookie_expires_malformed.md) — Set-Cookie Expires is readable but derives from no HTTP-date
- [cookie_expires_missing](../violations/cookie_expires_missing.md) — Set-Cookie Expires attribute carries no value
- [cookie_flag_value_forbidden](../violations/cookie_flag_value_forbidden.md) — Set-Cookie writes a value on a flag attribute
- [cookie_max_age_malformed](../violations/cookie_max_age_malformed.md) — Set-Cookie Max-Age is not a number a user agent will read
- [cookie_max_age_missing](../violations/cookie_max_age_missing.md) — Set-Cookie Max-Age attribute carries no value
- [cookie_pair_equals_missing](../violations/cookie_pair_equals_missing.md) — A Cookie pair is written without its '='
- [cookie_pair_missing](../violations/cookie_pair_missing.md) — Set-Cookie carries no cookie-pair
- [cookie_path_leading_slash_missing](../violations/cookie_path_leading_slash_missing.md) — Set-Cookie Path attribute is not rooted at `/`
- [cookie_path_missing](../violations/cookie_path_missing.md) — Set-Cookie Path attribute carries no value
- [cookie_same_site_invalid](../violations/cookie_same_site_invalid.md) — Set-Cookie SameSite names no policy the grammar defines
- [cookie_same_site_missing](../violations/cookie_same_site_missing.md) — Set-Cookie SameSite attribute carries no value
- [cookie_secure_missing](../violations/cookie_secure_missing.md) — A SameSite=None cookie is not Secure
- [cookie_value_character_forbidden](../violations/cookie_value_character_forbidden.md) — Cookie value holds a character outside cookie-octet
- [domain_name_whitespace_or_control_forbidden](../violations/domain_name_whitespace_or_control_forbidden.md) — Domain name holds whitespace or a control character
- [http_date_malformed](../violations/http_date_malformed.md) — Timestamp derives from no HTTP-date format
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 6265 §5.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.1): Dates — the algorithm a user agent MUST use to parse a cookie-date: delimiter-separated tokens, `-` among the delimiters, a two-to-four-digit year, and no zone read at all
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

### ❌ Bad — Expires names no instant at all

```http
Set-Cookie: SID=1; Expires=NotADate
```

### ❌ Bad — the hyphenated form every user agent reads, which is still not the rfc1123-date § 4.1.1 asks a sender for

```http
Set-Cookie: SID=1; Expires=Wed, 27-Aug-2036 02:28:19 GMT
```

### ❌ Bad — a bare token has no '=', so it is no cookie-pair at all

```http
Set-Cookie: SID
```

### ❌ Bad — a comma is outside cookie-octet

```http
Set-Cookie: SID=abc,def
```
