<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_cookie_path_validity

## Description

Validate the `Path` attribute in `Set-Cookie` header fields. The `Path` attribute should be a valid RFC 6265 `path-value` that begins with `/`, does not contain control characters or `;`, and uses valid percent-encodings where applicable. Raw non-ASCII characters are rejected by this rule — non-ASCII data should be percent-encoded (see RFC 3986 §2.1). This rule is intentionally stricter than RFC 6265: it also rejects unencoded whitespace in the `Path` attribute (spaces should be sent as `%20`) to reduce ambiguity in cookie scope and avoid syntactic errors that can affect cookie delivery and security.

## Specifications
- [RFC 6265 §5.2.4 — Path attribute](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4) — defines the `Path` attribute syntax and semantics (including `path-value`).
- [RFC 9110 §5.6.3 — Whitespace](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3) — rationale for being conservative about whitespace in header fields; this rule adopts a stricter profile by disallowing unencoded whitespace in cookie paths.

## Configuration

To enable the rule, add an entry to your rules config. Example:

```toml
[rules.message_cookie_path_validity]
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
