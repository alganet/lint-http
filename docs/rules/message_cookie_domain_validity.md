<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_cookie_domain_validity

## Description

Validate the `Domain` attribute of `Set-Cookie` header values. This rule checks that
`Domain` values are syntactically valid domain names (no spaces, valid label characters,
label length and overall length limits) and flags uses that are likely incorrect, such as
IP addresses or empty values. A leading `.` is tolerated for historical reasons but is
reported as deprecated.

## Specifications

- [RFC 6265 §5.2.3 — `Domain` attribute semantics and format](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3)
- [RFC 1035 — Domain name label rules (length, allowed characters)](https://www.rfc-editor.org/rfc/rfc1035.html)

## Configuration

```toml
[rules.message_cookie_domain_validity]
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
