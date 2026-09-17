<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Header Presence for CORS Preflight and Cross-Origin Absolute-form Requests

## Description

This rule enforces that requests which indicate cross-origin intent include an `Origin` header. In particular:

- CORS preflight requests (an `OPTIONS` request with `Access-Control-Request-Method` or `Access-Control-Request-Headers`) MUST include an `Origin` header.
- If a client uses an absolute-form request-target whose origin differs from the `Host` header, the request is treated as cross-origin and SHOULD include an `Origin` header.

The rule validates that `Origin` is present where required and that its value is syntactically plausible (a serialized origin such as `https://example.com` or the literal `null`). This rule applies to client requests.

## Violations

- [origin_malformed](../violations/origin_malformed.md) — An Origin derives from neither null nor a serialized origin
- [origin_missing](../violations/origin_missing.md) — A request that must say where it came from carries no Origin
- [origin_path_forbidden](../violations/origin_path_forbidden.md) — An Origin names a path the production has no component for
- [uri_character_forbidden](../violations/uri_character_forbidden.md) — Value holds a character no URI is written with
- [uri_scheme_character_forbidden](../violations/uri_scheme_character_forbidden.md) — URI scheme holds a character outside letters, digits, '+', '-' and '.'
- [uri_scheme_empty](../violations/uri_scheme_empty.md) — URI scheme is empty
- [uri_scheme_leading_letter_missing](../violations/uri_scheme_leading_letter_missing.md) — URI scheme does not begin with a letter

## Specifications

- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Origin header field syntax — `origin-list-or-null` is the literal `null` or a list of `serialized-origin`, and a `serialized-origin` is a scheme, `://`, a host and an optional port, with no path component
- [Fetch §3.2](https://fetch.spec.whatwg.org/#origin-header): The `Origin` request header — where a fetch originates from, sent for CORS fetches and for any request whose method is neither GET nor HEAD
- [MDN Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin): Origin
- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters — the limited set a URI is composed from, every other octet being percent-encoded before the reference is formed
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon

## Configuration

```toml
[rules.request_origin_header_present_for_cors]
enabled = true
```

## Examples

### ✅ Good (preflight)

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Origin: https://example.org
Access-Control-Request-Method: POST
```

### ✅ Good (absolute-form same origin)

```http
GET http://example.com/resource HTTP/1.1
Host: example.com
```

### ❌ Bad (preflight missing Origin)

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Access-Control-Request-Method: POST
```

### ❌ Bad (absolute-form to other origin missing Origin)

```http
GET http://other.example/resource HTTP/1.1
Host: example.com
```
