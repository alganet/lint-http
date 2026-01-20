<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_accept_ranges_and_206_consistency

## Description

When a server returns a 206 (Partial Content) response it indicates that the request was satisfied by returning a range of the representation. Servers SHOULD advertise support for range requests using the `Accept-Ranges` header; an `Accept-Ranges: none` value contradicts a 206 response and is invalid in that context. This rule warns when a 206 response does not advertise supported range units, or when the advertised units contradict the `Content-Range` header.

## Specifications

- [RFC 7233 §4.1 — 206 Partial Content: single-part 206 responses MUST include a `Content-Range` header describing the enclosed range.](https://www.rfc-editor.org/rfc/rfc7233.html#section-4.1)
- [RFC 9110 §7.3.4 — `Accept-Ranges`: response header that advertises supported `range-unit` tokens or `none`.](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.4)

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
