<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_accept_ranges_on_partial_content

## Description

Clients should track server advertising of range support via the `Accept-Ranges` response header and avoid sending `Range` requests when the server has explicitly advertised `Accept-Ranges: none`. If a previous response for the same resource was `206 Partial Content` but did not advertise `Accept-Ranges`, clients should be conservative and avoid sending subsequent `Range` requests unless the server signals support.

## Specifications

- [RFC 9110 §7.3.4 — `Accept-Ranges`: response header that advertises supported `range-unit` tokens or `none`.](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.4)
- [RFC 7233 §4.1 — `206 Partial Content` and `Content-Range`.](https://www.rfc-editor.org/rfc/rfc7233.html#section-4.1)

## Configuration

```toml
[rules.client_accept_ranges_on_partial_content]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — server advertises support for bytes and client uses bytes

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes

GET /resource HTTP/1.1
Range: bytes=0-499
```

### ❌ Bad — server explicitly rejects ranges, client should not send Range

```http
HTTP/1.1 200 OK
Accept-Ranges: none

GET /resource HTTP/1.1
Range: bytes=0-499
```

### ❌ Bad — previous response was 206 but did not advertise Accept-Ranges (client should not assume support)

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234

GET /resource HTTP/1.1
Range: bytes=500-999
```
