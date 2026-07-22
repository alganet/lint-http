<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Permissions Policy Directives Valid

## Description

Validate `Permissions-Policy` HTTP response header directives for correct feature identifiers and member value forms. The header must be a structured-field dictionary (RFC 9651) and each directive must map a feature identifier (alphanumerics and hyphens) to an allowlist value (token `*`, token `self`, a `"string"`, or an inner-list `( ... )`). The optional `report-to` parameter (on the member value) must be a quoted-string when present.

## Specifications

- [Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/#permissions-policy-http-header-field): Permissions-Policy HTTP header (directive syntax and serialization). No section: an editor's draft renumbers — this reference said §5.2, the header field is now §6.1
- [RFC 9651 §3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3): Structured Field Values for HTTP, §3–§5 (Items, Lists, Dictionaries)

## Configuration

```toml
[rules.message_permissions_policy_directives_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation=(self "https://example.com"), fullscreen=(), payment=("https://pay.example") ; report-to="endpoint"
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation ;  # missing '=value' -> invalid
```

```http
HTTP/1.1 200 OK
Permissions-Policy: bad_name=(self)  # invalid feature identifier (underscore)
```

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation=(self);report-to=endpoint  # report-to must be a quoted-string
```
