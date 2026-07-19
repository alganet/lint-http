<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Accept Ranges On Partial Content

## Description

Clients should track server advertising of range support via the `Accept-Ranges` response header and avoid sending `Range` requests when the server has explicitly advertised `Accept-Ranges: none`. If a previous response for the same resource was `206 Partial Content` but did not advertise `Accept-Ranges`, clients should be conservative and avoid sending subsequent `Range` requests unless the server signals support.

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: response header that advertises supported `range-unit` tokens or `none`
- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): `206 Partial Content` and `Content-Range`. RFC 7233 §4.1 defined them; RFC 9110 obsoleted RFC 7233

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
