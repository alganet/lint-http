<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Status Code Validity

## Description

HTTP/3 does not support the `101 (Switching Protocols)` informational status code. The protocol upgrade mechanism used in HTTP/1.1 has no equivalent in HTTP/3; applications that require protocol switching should use extended CONNECT (RFC 9220) instead.

Additionally, informational (1xx) responses in HTTP/3 consist of only a HEADERS frame and must not include a message body, `Content-Length` header, or trailer fields.

This rule applies when the request version is `HTTP/3`. Response properties are checked only when the response's own version is also `HTTP/3`; in a reverse-proxy setup the upstream response may arrive via HTTP/1.1 where `101` is legitimate.

## Specifications

- [RFC 9114 §4.5](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5) — HTTP Upgrade
- [RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1) — HTTP Message Exchanges
- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2) — Informational 1xx
- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) — Bootstrapping WebSockets with HTTP/3

## Configuration

```toml
[rules.server_http3_status_code_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
HTTP/3 100 Continue
```

```http
HTTP/3 103 Early Hints
Link: </style.css>; rel=preload; as=style
```

```http
HTTP/3 200 OK
Content-Type: text/html
```

### ❌ Bad

```http
HTTP/3 101 Switching Protocols
Upgrade: websocket
```

HTTP/3 does not support protocol switching; use extended CONNECT instead.

```http
HTTP/3 100 Continue
Content-Length: 0
```

Informational responses must not include `Content-Length`.

```http
HTTP/3 103 Early Hints
Link: </style.css>; rel=preload; as=style

<body data follows>
```

Informational responses must not contain a message body.
