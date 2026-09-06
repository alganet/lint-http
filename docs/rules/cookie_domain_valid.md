<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cookie Domain Valid

## Description

Validate the `Domain` attribute of `Set-Cookie` header values. This rule checks that
`Domain` values are syntactically valid domain names (no spaces, valid label characters,
label length and overall length limits) and flags uses that are likely incorrect, such as
IP addresses or empty values. A leading `.` is tolerated for historical reasons but is
reported as deprecated.

## Specifications

- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters
- [RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4): Size limits — a name is 255 octets or less
- [RFC 6265 §5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3): Domain matching — a cookie-domain that is not a host name matches only the identical string, so an IP address scopes the cookie to nothing it can be sent for
- [RFC 6265 §5.2.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3): `Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035

## Configuration

```toml
[rules.cookie_domain_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Set-Cookie: SID=1; Domain=example.com
```

### ✅ Good (attribute order tolerated)

```http
Set-Cookie: SID=1; Secure; Domain=example.com
```

### ❌ Bad — IP address used as Domain

```http
Set-Cookie: SID=1; Domain=192.168.0.1
```

### ❌ Bad — invalid characters in domain

```http
Set-Cookie: SID=1; Domain=exa_mple.com
```

### ❌ Bad — empty domain value

```http
Set-Cookie: SID=1; Domain=
```

### ❌ Bad — leading dot is deprecated (this rule reports it)

```http
Set-Cookie: SID=1; Domain=.example.com
```
