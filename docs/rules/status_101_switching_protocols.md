<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Status 101 Switching Protocols

## Description

Validates that `101 Switching Protocols` responses follow correct HTTP upgrade semantics. The rule checks:

- The client must have requested the upgrade via the `Upgrade` header; unsolicited 101 responses are a protocol violation.
- The 101 itself must name what it switched to: RFC 9110 § 15.2.2 requires an `Upgrade` header field in the response, and the requirement holds whatever the request said.
- The protocol chosen in the response `Upgrade` header must match one offered by the client.
- 101 must not be sent for HTTP/1.0 requests (Upgrade is an HTTP/1.1+ mechanism), or over HTTP/2 or HTTP/3 where the Upgrade mechanism is not supported.
- After a successful 101 exchange, no further HTTP messages should appear on the same connection — the connection has been handed off to the upgraded protocol.

**The client's obligation and the server's are reported separately.** They are written for different senders and neither is a measurement the other needs, so a 101 that answers a request carrying no `Upgrade` *and* names no protocol of its own draws both findings rather than the first one alone.

## Violations

- [status_101_ignored](../violations/status_101_ignored.md) — HTTP continues on a connection a 101 handed off
- [status_101_protocol_forbidden](../violations/status_101_protocol_forbidden.md) — A 101 switches to a protocol the client did not indicate
- [status_101_unsolicited](../violations/status_101_unsolicited.md) — 101 Switching Protocols is sent on a version with no upgrade mechanism
- [upgrade_101_empty](../violations/upgrade_101_empty.md) — A 101 response names no protocol on its Upgrade field
- [upgrade_101_missing](../violations/upgrade_101_missing.md) — A 101 response carries no Upgrade field

## Specifications

- [RFC 9110 §15.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2): 101 Switching Protocols — the status code is a change in the application protocol being used on this connection, and the response MUST generate an `Upgrade` field naming the protocol(s) in effect after it
- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the mechanism a 101 answers, the MUST NOT on switching to a protocol the client did not indicate, and the MUST that a server ignore an `Upgrade` received in an HTTP/1.0 request
- [RFC 9113 §8.6](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6): The Upgrade Header Field — HTTP/2 does not support the 101 status code, and says why: its semantics are not applicable to a multiplexed protocol
- [RFC 9114 §4.5](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5): HTTP Upgrade — the only place RFC 9114 mentions 101, withholding the upgrade mechanism and the status code together

## Configuration

```toml
[rules.status_101_switching_protocols]
enabled = true
```

## Examples

### ✅ Good — client requests upgrade and server agrees

```http
> GET /chat HTTP/1.1
> Upgrade: websocket
> Connection: Upgrade

< HTTP/1.1 101 Switching Protocols
< Upgrade: websocket
< Connection: Upgrade
```

### ✅ Good — server declines upgrade (non-101 response)

```http
> GET /resource HTTP/1.1
> Upgrade: h2c
> Connection: Upgrade

< HTTP/1.1 200 OK
```

### ❌ Bad — unsolicited 101 (no Upgrade in request)

```http
> GET /resource HTTP/1.1

< HTTP/1.1 101 Switching Protocols
< Upgrade: websocket
```

### ❌ Bad — protocol mismatch

```http
> GET /chat HTTP/1.1
> Upgrade: websocket
> Connection: Upgrade

< HTTP/1.1 101 Switching Protocols
< Upgrade: h2c
< Connection: Upgrade
```

### ❌ Bad — 101 over HTTP/2

```http
> GET /chat HTTP/2
> Upgrade: websocket

< HTTP/2 101 Switching Protocols
< Upgrade: websocket
```

### ❌ Bad — HTTP traffic after 101 on the same connection

```http
> GET /chat HTTP/1.1
> Upgrade: websocket
> Connection: Upgrade

< HTTP/1.1 101 Switching Protocols
< Upgrade: websocket
< Connection: Upgrade

> GET /other HTTP/1.1

< HTTP/1.1 200 OK
```
