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
- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Historical serialized-origin shape (`scheme "://" host [ ":" port ]`) the conservative validator implements; Fetch supplants the serialization

## Configuration

```toml
[rules.message_timing_allow_origin_validity]
enabled = true
severity = "warn"
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
