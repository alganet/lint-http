<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Status Code Validity

## Description

HTTP/3 does not support the `101 (Switching Protocols)` informational status code. The protocol upgrade mechanism used in HTTP/1.1 has no equivalent in HTTP/3; applications that require protocol switching should use extended CONNECT (RFC 9220) instead.

This rule applies when the request version is `HTTP/3`. The response is checked only when its own version is also `HTTP/3`; in a reverse-proxy setup the upstream response may arrive via HTTP/1.1, where `101` is legitimate.

**One status code, and only what HTTP/3 says about it.** This rule also used to report a `Content-Length`, a message body, or a trailer section on a `1xx` response. Those rest on RFC 9110 §15.2 — *"A 1xx response is terminated by the end of the header section; it cannot contain content or trailers"* — which is not a sentence about HTTP/3, so enforcing it here meant the same defect over HTTP/1.1 or HTTP/2 went unreported. `no_body_for_1xx_204_304` enforces it on every version, and for `204` and `304` as well as `1xx`.

## Specifications

- [RFC 9114 §4.5](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5): HTTP Upgrade
- [RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1): HTTP Message Framing, where interim and final responses are described. This note said HTTP Message Exchanges, which is not a section RFC 9114 has
- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): Informational 1xx — where 101 is defined, and where the rule 101 breaks is written. Its sentence forbidding content and trailers on a 1xx is version-independent and is enforced by no_body_for_1xx_204_304, not here
- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html): Bootstrapping WebSockets with HTTP/3

## Configuration

```toml
[rules.http3_status_code_valid]
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
