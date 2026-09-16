<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Timing-Allow-Origin Header Validity

## Description

Validate the `Timing-Allow-Origin` response header values. The header's value
must be `*` (wildcard), the lowercase literal `null` (the grammar's `%s"null"`
is case-sensitive), or one or more serialized origins (`scheme://host[:port]`).
Multiple header fields are allowed and their values are combined using HTTP
list semantics. This rule detects header values that cannot be decoded as
visible US-ASCII, an entirely empty header value, and invalid origin
serializations.

## Specifications

- [Resource Timing §3.5.2](https://www.w3.org/TR/resource-timing/#sec-timing-allow-origin): `Timing-Allow-Origin` response header and its ABNF
- [Fetch §3.2](https://fetch.spec.whatwg.org/#origin-header): `origin-or-null` and `serialized-origin`, the productions the grammar's members resolve to (`null` is case-sensitive)
- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Origin header field syntax — `origin-list-or-null` is the literal `null` or a list of `serialized-origin`, and a `serialized-origin` is a scheme, `://`, a host and an optional port, with no path component
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon
- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters — the limited set a URI is composed from, every other octet being percent-encoded before the reference is formed

## Configuration

```toml
[rules.timing_allow_origin_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: *
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https://example.com
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https://a, https://b
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https:///foo
```

### ❌ Bad `null` is case-sensitive

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: NULL
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: 
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: 	
```
