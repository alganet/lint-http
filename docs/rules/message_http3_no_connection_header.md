<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_http3_no_connection_header

## Description

HTTP/3 does not use the `Connection` header field to indicate connection-specific options. Connection-specific header fields such as `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, and `Upgrade` have no meaning in HTTP/3 and their presence indicates a malformed message. An endpoint MUST NOT generate an HTTP/3 field section containing any of these headers.

The only exception is the `TE` header field, which MAY be present in an HTTP/3 request but MUST NOT contain any value other than `trailers`. Since `TE` is a request-only field (RFC 9110 §10.1.4), any `TE` header in an HTTP/3 response is also invalid.

Request headers are checked when the request version is `HTTP/3`. Response headers are checked only when the response's own version is `HTTP/3`; in a reverse-proxy setup the upstream response may arrive via HTTP/1.1 or HTTP/2 and legitimately carry connection-specific headers that are stripped before forwarding over HTTP/3.

## Specifications

- [RFC 9114 §4.2 — HTTP Fields](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2)
- [RFC 9110 §7.6.1 — Connection](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)
- [RFC 9110 §10.1.4 — TE](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4)

## Configuration

```toml
[rules.message_http3_no_connection_header]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/3
Host: example.com
Accept: text/html
```

```http
GET /resource HTTP/3
Host: example.com
TE: trailers
```

### ❌ Bad

```http
GET /resource HTTP/3
Host: example.com
Connection: keep-alive
```

```http
POST /data HTTP/3
Host: example.com
Transfer-Encoding: chunked
```

```http
GET /resource HTTP/3
Host: example.com
Upgrade: websocket
```

```http
GET /resource HTTP/3
Host: example.com
TE: gzip, trailers
```
