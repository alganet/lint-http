<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Header Presence for CORS Preflight Requests

## Description

This rule enforces that a CORS preflight request includes an `Origin` header: an `OPTIONS` request with `Access-Control-Request-Method` or `Access-Control-Request-Headers` MUST include one, and its value must be syntactically plausible (a serialized origin such as `https://example.com` or the literal `null`). This rule applies to client requests.

**A `Host` that disagrees with the request-target is not a cross-origin request.** `Origin` names where a fetch was initiated — the origin of the document or worker that made it — and nothing about the request's own target and `Host` can say what that was. This rule used to treat an absolute-form target whose authority differs from `Host` as cross-origin and ask for an `Origin` header, which is a requirement no specification states and a repair that fixes nothing: the two fields naming different authorities is its own defect, RFC 9112 §3.2's over HTTP/1.1 and RFC 9113 §8.3.1's and RFC 9114 §4.3.1's over the later versions, and `host_and_authority_consistent` reports it for all three.

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
