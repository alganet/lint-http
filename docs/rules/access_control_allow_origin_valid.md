<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Access-Control-Allow-Origin Syntax

## Description

This rule checks that the `Access-Control-Allow-Origin` response header is syntactically valid: it must be a single value and that value must be either `*`, `null`, or a valid serialized-origin (scheme://host[:port]). Multiple header fields or comma-separated lists are not allowed per the CORS semantics and will be flagged as violations.

## Specifications

- [MDN Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin): Access-Control-Allow-Origin
- [Fetch §3.3.3](https://fetch.spec.whatwg.org/#http-access-control-allow-origin): `Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`
- [Fetch §3.2](https://fetch.spec.whatwg.org/#origin-header): Governing origin syntax: `serialized-origin` ends at its authority, so a path (not even a trailing slash), a query or a fragment all disqualify it; the host inside it is a `reg-name` or a bracketed `IP-literal`, so a character outside those productions or a malformed percent-encoding disqualifies it too; and `origin-or-null`'s `null` is case-sensitive
- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Historical origin syntax the non-`*` value is validated against — `serialized-origin = scheme "://" host [ ":" port ]`, and `null` via origin-list-or-null; Fetch §3.2 supplants it

## Configuration

```toml
[rules.access_control_allow_origin_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a, https://b
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a
Access-Control-Allow-Origin: https://b
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: example.com
```

### ❌ Bad a serialized origin has no path, not even a trailing slash

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com/
```
