<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cookie Path Valid

## Description

Validate the `Path` attribute in `Set-Cookie` header fields. The `Path` attribute should be a valid RFC 6265 `path-value` that begins with `/`, does not contain control characters or `;`, and uses valid percent-encodings where applicable. Raw non-ASCII characters are rejected by this rule — non-ASCII data should be percent-encoded (see RFC 3986 §2.1). This rule is intentionally stricter than RFC 6265: it also rejects unencoded whitespace in the `Path` attribute (spaces should be sent as `%20`) to reduce ambiguity in cookie scope and avoid syntactic errors that can affect cookie delivery and security.

## Violations

- [cookie_path_control_character_forbidden](../violations/cookie_path_control_character_forbidden.md) — Set-Cookie Path attribute holds a control character
- [cookie_path_empty](../violations/cookie_path_empty.md) — Set-Cookie Path attribute is empty
- [cookie_path_leading_slash_missing](../violations/cookie_path_leading_slash_missing.md) — Set-Cookie Path attribute is not rooted at `/`
- [cookie_path_missing](../violations/cookie_path_missing.md) — Set-Cookie Path attribute carries no value
- [cookie_path_non_ascii_character_forbidden](../violations/cookie_path_non_ascii_character_forbidden.md) — Set-Cookie Path attribute holds a raw non-ASCII character
- [cookie_path_whitespace_invalid](../violations/cookie_path_whitespace_invalid.md) — Set-Cookie Path attribute holds unencoded whitespace
- [percent_encoding_digits_missing](../violations/percent_encoding_digits_missing.md) — Percent-encoding stops before its two hexadecimal digits
- [percent_encoding_malformed](../violations/percent_encoding_malformed.md) — Percent-encoding is not two hexadecimal digits

## Specifications

- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits every `%` still owes
- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 6265 §5.2](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2): The Set-Cookie header parsing algorithm — where the `;` split, the WSP trim and the case-insensitive `Path` match come from
- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — rationale for being conservative about whitespace in header fields; this rule adopts a stricter profile by disallowing unencoded whitespace in cookie paths

## Configuration

```toml
[rules.cookie_path_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Set-Cookie: SID=31d4d96e407aad42; Path=/; HttpOnly; Secure
```

### ✅ Good (percent-encoded)

```http
HTTP/1.1 200 OK
Set-Cookie: user=alice; Path=/users/alice%2Fprofile
```

### ❌ Bad (missing leading slash)

```http
HTTP/1.1 200 OK
Set-Cookie: SID=abcd; Path=login
```

### ❌ Bad (contains space)

```http
HTTP/1.1 200 OK
Set-Cookie: SID=abcd; Path=/has space
```

### ❌ Bad (raw non-ASCII)

```http
HTTP/1.1 200 OK
Set-Cookie: SID=abcd; Path=/café
```

### ✅ Good (non-ASCII percent-encoded)

```http
HTTP/1.1 200 OK
Set-Cookie: SID=abcd; Path=/caf%C3%A9
```
