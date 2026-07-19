<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept Ranges And 206 Consistency

## Description

When a server returns a 206 (Partial Content) response it indicates that the request was satisfied by returning a range of the representation. Servers SHOULD advertise support for range requests using the `Accept-Ranges` header; an `Accept-Ranges: none` value contradicts a 206 response and is invalid in that context. This rule warns when a 206 response does not advertise supported range units, or when the advertised units contradict the `Content-Range` header.

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): `206 Partial Content`: a single-part 206 MUST include a `Content-Range`. RFC 7233 §4.1 defined it; RFC 9110 obsoleted RFC 7233
- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: response header that advertises supported `range-unit` tokens or `none`

## Configuration

```toml
[rules.message_accept_ranges_and_206_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: bytes
```

### ✅ Good (Accept-Ranges may include multiple supported units)

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: bytes, other-unit
```

### ✅ Good — multiple header fields combined

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: pages
Accept-Ranges: bytes
```

### ❌ Bad — Accept-Ranges explicitly says none

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: none
```

### ❌ Bad — Accept-Ranges missing (should advertise support)

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
```

### ❌ Bad — Content-Range unit not advertised

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: pages
```
