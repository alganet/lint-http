<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cookie Path Valid

## Description

Validate the `Path` attribute in `Set-Cookie` header fields. The `Path` attribute should be a valid RFC 6265 `path-value` that begins with `/`, does not contain control characters or `;`, and uses valid percent-encodings where applicable. Raw non-ASCII characters are rejected by this rule — non-ASCII data should be percent-encoded (see RFC 3986 §2.1). This rule is intentionally stricter than RFC 6265: it also rejects unencoded whitespace in the `Path` attribute (spaces should be sent as `%20`) to reduce ambiguity in cookie scope and avoid syntactic errors that can affect cookie delivery and security.

## Specifications

- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits a `%` in a cookie path still owes
- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; `path-value` excludes control characters and `;`
- [RFC 6265 §5.2](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2): The Set-Cookie header parsing algorithm — where the `;` split, the WSP trim and the case-insensitive `Path` match come from
- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — rationale for being conservative about whitespace in header fields; this rule adopts a stricter profile by disallowing unencoded whitespace in cookie paths

## Configuration

```toml
[rules.cookie_path_valid]
enabled = true
severity = "warn"
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
