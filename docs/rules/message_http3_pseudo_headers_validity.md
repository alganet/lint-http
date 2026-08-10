<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Pseudo-Headers Validity

## Description

HTTP/3 requests encode control data as pseudo-header fields. This rule validates that every request includes exactly one `:method` pseudo-header field and that every non-CONNECT request includes a non-empty `:path` pseudo-header field.

For schemes with a mandatory authority component (including `http` and `https`), the HTTP/3 specification requires that the request contain either an `:authority` pseudo-header field or a `Host` header field. This rule enforces that requirement by checking that at least one of `:authority` or `Host` is present. It does not validate the `:scheme` pseudo-header, because the canonical transaction model used by lint-http does not retain scheme information for origin-form requests.

**This rule reads requests only.** RFC 9114 §4.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation here. The range that value must fall in is RFC 9110 §15's and is the same for every HTTP version — §4.3.2 states none of its own — so an out-of-range status is reported by `server_status_code_valid_range`, whatever version carried it. This rule used to report it too, but only when both ends spoke HTTP/3.

## Specifications

- [RFC 9114 §4.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3): HTTP Control Data
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): Request Pseudo-Header Fields
- [RFC 9114 §4.3.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2): Response Pseudo-Header Fields
- [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4): The CONNECT Method
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource (asterisk-form request target)

## Configuration

```toml
[rules.message_http3_pseudo_headers_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/3
Host: example.com
Accept: text/html
```

```http
OPTIONS * HTTP/3
Host: example.com
```

```http
CONNECT example.com:443 HTTP/3
```

```http
HTTP/3 200 OK
Content-Type: text/html
```

### ❌ Bad

```http
GET /resource HTTP/3
Accept: text/html
```

```http
 HTTP/3
Host: example.com
```

```http
GET * HTTP/3
Host: example.com
```

```http
HTTP/3 0
```
