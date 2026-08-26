<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket handshake validity

## Description

Measures the server's half of a WebSocket opening handshake against the request it answers, following the list RFC 6455 § 4.1 gives a client for validating that response:

- `Upgrade` is `websocket`. In a response that is one value, not a list: § 4.1 has the client fail the connection when the field *contains a value that is not an ASCII case-insensitive match* for `websocket`, and § 4.2.2 asks for the field *with value "websocket"*. The request's `Upgrade`, by contrast, need only *include the "websocket" keyword*, and `sec_websocket_headers_consistent` reads it that way.
- `Connection` names the `Upgrade` connection-option — a list, one item later in the same numbered list.
- `Sec-WebSocket-Accept` is the base64 SHA-1 of the request's `Sec-WebSocket-Key` concatenated with the well-known GUID. The finding names the value the server should have written.
- `Sec-WebSocket-Extensions`, when present, names only extensions the request offered.
- `Sec-WebSocket-Protocol`, when present, is a single `token` — the server's production, where the client's is a list — that is not the empty string and that the request offered. A server agreeing to no subprotocol sends no field.

One finding is about the request rather than the response, and it is one only a rule holding both halves can make: a `101` answering a handshake whose `Sec-WebSocket-Key` is absent or is not a sixteen-octet nonce. RFC 6455 § 4.2.1 requires a server to stop processing such a handshake and answer with an error status, so completing it is the server's defect; the value itself is reported separately, against the client, by `sec_websocket_headers_consistent`.

**Only `101` responses are measured.** RFC 6455 § 4.2.2 lists what a server sends *if the server chooses to accept the incoming connection*, and names five things it does instead — a `401` challenge, a `3xx` redirect, a `403` for an origin it will not serve, a `404` for a resource it does not have, a `426` for a version it does not speak. § 4.1 hands all of them to ordinary HTTP processing, where the rest of this catalogue measures them, so a non-`101` answer is a refusal rather than a malformed handshake.

Only HTTP/1.x exchanges are measured: over HTTP/2 and HTTP/3 the handshake is an extended CONNECT carrying `:protocol` (RFC 8441, RFC 9220), where `Connection` and `Upgrade` are forbidden and `Sec-WebSocket-Accept` is not sent at all.

Two neighbours own the sentences this rule does not. The obligation to send an `Upgrade` in *any* `101`, and to name in it only protocols the client offered, is RFC 9110's and belongs to `status_101_switching_protocols`. `Sec-WebSocket-Version: 13` is asked of the request by `sec_websocket_headers_consistent` and is deliberately not asked of the server here: RFC 6455 § 4.2.1's list makes every one of its items a MUST-refuse, while § 4.2.2 aborts a handshake only for a version *that does not match a version understood by the server* — a fact about the server, which a `101` is that server asserting. `Sec-WebSocket-Extensions` is measured here only against what the request offered; its own grammar (`extension-list`, `extension-param`) is `message_sec_websocket_extensions_syntax`'s, in both directions.

## Specifications

- [RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1): Client Requirements — the numbered list a client validates the server's response against, and the sentence handing every non-101 back to plain HTTP
- [RFC 6455 §4.2.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1): Reading the Client's Opening Handshake — the description a handshake has to match, and the requirement to refuse one that does not, which is what makes a 101 over a malformed key the server's defect
- [RFC 6455 §4.2.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2): Sending the Server's Opening Handshake — what a server sends if it accepts, the five things it sends instead if it does not, and how `Sec-WebSocket-Accept`, `/subprotocol/` and `/extensions/` are derived from the request
- [RFC 6455 §4.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3): Collected ABNF — `Sec-WebSocket-Protocol-Server = token` against the client's `1#token`, and the `extension` production whose first half is the name
- [RFC 6455 §9.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1): Negotiating Extensions — the server's list is the extensions in use, each extension's own document defines what a valid answer to its parameters is, and an `extension-token` is a registered name
- [RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441.html#section-5): Updates RFC 6455: over HTTP/2 the handshake is an extended CONNECT, `Connection` and `Upgrade` MUST NOT be included, and `Sec-WebSocket-Accept` is not processed — the sentences behind this rule's version gate
- [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3): Carries RFC 8441's mechanism to HTTP/3 with identical semantics

## Configuration

```toml
[rules.websocket_handshake_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### ✅ Good (a refusal is not a malformed handshake)

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="chat"
```

### ❌ Bad (mismatched accept)

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: WRONG==
```

### ❌ Bad (a subprotocol the client never offered)

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: superchat
```
