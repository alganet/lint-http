<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Warning Header Syntax

## Description

Validate `Warning` header members follow the syntax described in RFC 7234 §5.5. Each member (a comma-separated `warn-value`) consists of:

- A three-digit `warn-code` (e.g., `110`, `214`)
- Whitespace and a `warn-agent` (host[:port] or pseudonym)
- Whitespace and a `warn-text` which MUST be a `quoted-string`
- Optionally, whitespace and a `warn-date` which MUST be a `quoted-string` containing an IMF-fixdate (an HTTP-date)

This rule flags empty members, invalid 3-digit codes, missing or unquoted `warn-text`, malformed `warn-date` (including invalid HTTP dates), and non-UTF8 header values.

## Specifications

- [RFC 7234 §5.5](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5): Warning header field
- [RFC 9110 §7.1.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1.1.1): HTTP-date (IMF-fixdate)

## Configuration

```toml
[rules.message_warning_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Warning: 110 - "Response is stale"
```

```http
HTTP/1.1 200 OK
Warning: 214 example.com:80 "Transformation applied"
```

```http
HTTP/1.1 200 OK
Warning: 214 example.com "Text" "Wed, 21 Oct 2015 07:28:00 GMT"
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Warning: ,
```

```http
HTTP/1.1 200 OK
Warning: 21a host "text"
```

```http
HTTP/1.1 200 OK
Warning: 214 host text
```

```http
HTTP/1.1 200 OK
Warning: 214 host "x" "not-a-date"
```
