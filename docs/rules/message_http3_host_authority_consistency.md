<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Host and Authority Consistency

## Description

In HTTP/3 the `:authority` pseudo-header field carries the authority component of the target URI. When a request also includes a `Host` header, both fields MUST contain the same value; a mismatch indicates either a misconfigured intermediary or a potential request-smuggling vector. A server SHOULD treat such a request as malformed.

If both fields are present, neither may be empty for `http` or `https` URIs. The comparison is case-insensitive for the hostname portion, as required by URI syntax (RFC 3986 §3.2.2).

This rule only applies to HTTP/3 requests. When the request version is not HTTP/3, or when only one of the two fields is present, no check is performed.

## Specifications

- [RFC 9114 §4.3.1 — Request Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1)
- [RFC 9110 §7.2 — Host and :authority](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2)
- [RFC 3986 §3.2.2 — Host](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)

## Configuration

```toml
[rules.message_http3_host_authority_consistency]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/3
Host: example.com
```

```http
GET /resource HTTP/3
Host: example.com:8080
```

### ❌ Bad

```http
GET /resource HTTP/3
Host: other.com
```

The `:authority` pseudo-header targets `example.com` but the `Host` header says `other.com`.

```http
GET /resource HTTP/3
Host: example.com:9090
```

The port in `:authority` (`8080`) differs from the port in the `Host` header (`9090`).

```http
GET /resource HTTP/3
Host:
```

The `Host` header is empty while `:authority` is present.
