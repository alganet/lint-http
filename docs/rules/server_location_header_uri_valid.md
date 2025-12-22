<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Location Header URI Valid

## Description

This rule checks that the `Location` response header, when present, is a syntactically valid URI-reference.
`Location` is commonly used in redirects and SHOULD be a URI-reference per the HTTP spec; malformed values can break clients.

## Specifications

- [RFC 9110 §7.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-location)
- [RFC 3986 §4](https://www.rfc-editor.org/rfc/rfc3986.html#section-4) — URI-reference syntax and percent-encoding

## Configuration

```toml
[rules.server_location_header_uri_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (absolute URI)

```http
HTTP/1.1 302 Found
Location: https://example.com/new-location
```

### ✅ Good (relative URI-reference)

```http
HTTP/1.1 302 Found
Location: /new-location?ref=1
```

### ❌ Bad (invalid percent-encoding)

```http
HTTP/1.1 302 Found
Location: /bad%2Gencoding
```

### ❌ Bad (contains whitespace)

```http
HTTP/1.1 302 Found
Location: https://example.com/ bad
```
