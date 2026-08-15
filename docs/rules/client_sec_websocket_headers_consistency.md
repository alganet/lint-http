<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Sec Websocket Headers Consistency

## Description

Measures a WebSocket opening handshake — a `GET` whose `Upgrade` field names `websocket` — against the requirements RFC 6455 § 4.1 lists for it:

- The request's HTTP version is at least `1.1`.
- `Connection` names the `Upgrade` connection-option.
- `Sec-WebSocket-Version` derives from the `version` production and names version `13`. A value that derives from the production but names another version is RFC 6455 § 4.4's version advertisement: it is reported as a handshake for a protocol this document does not define, and the answer it asks a server for is a `400` listing the versions the server speaks — which `server_sec_websocket_version_advertisement` is the rule that reads.
- `Sec-WebSocket-Key` is a base64-encoded sixteen-octet nonce. Whether that nonce was *chosen* randomly, which the same sentence also requires, is not something one captured message states.
- `Sec-WebSocket-Protocol`, when present, is a list of at least one subprotocol name, each a non-empty `token`, and no name written twice.

Only HTTP/1.x messages are measured. Over HTTP/2 and HTTP/3 the opening handshake is an extended CONNECT carrying a `:protocol` pseudo-header field (RFC 8441, RFC 9220), the `Connection` and `Upgrade` fields this rule reads are forbidden outright, and `Sec-WebSocket-Key` is not processed — so demanding them there would be advice a sender must not follow.

`Host` is asked for by the same list and reported by `client_host_header`; the server's half of the handshake is `stateful_websocket_handshake_validity`'s. RFC 6455 § 4.1 also requires an `Origin` field from a browser client, and nothing in a capture says whether a client is one — § 4.2.1 says as much, telling a server not to read a missing `Origin` as evidence either way — so no rule here reports its absence.

## Specifications

- [RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1): Client Requirements — the numbered list this rule measures: GET, HTTP version at least 1.1, `Upgrade: websocket`, the `Upgrade` connection-option, the `Sec-WebSocket-Key` nonce, `Sec-WebSocket-Version: 13`, and `Sec-WebSocket-Protocol`'s non-empty unique `token` members
- [RFC 6455 §4.2.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1): Reading the Client's Opening Handshake — the same list from the server's side, which is where the two case-insensitive comparisons and the `Origin` decline are stated
- [RFC 6455 §4.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3): Collected ABNF — `Sec-WebSocket-Key = base64-value-non-empty`, `Sec-WebSocket-Version-Client = version`, `Sec-WebSocket-Protocol-Client = 1#token`; the client's version field is one `version` and only the server's is a list
- [RFC 6455 §4.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.4): Supporting Multiple Versions — why a `Sec-WebSocket-Version` other than 13 is a version advertisement rather than a malformed value, and what a server owes it
- [RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441.html#section-5): Updates RFC 6455: over HTTP/2 the handshake is an extended CONNECT, `Connection` and `Upgrade` MUST NOT be included, and `Sec-WebSocket-Key` is not processed — the sentences behind this rule's version gate
- [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3): Carries RFC 8441's mechanism to HTTP/3 with identical semantics
- [RFC 4648 §3.3](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3): The instruction to reject encoded data holding a character outside the base alphabet, which is what makes a malformed `Sec-WebSocket-Key` reportable rather than merely unusual

## Configuration

```toml
[rules.client_sec_websocket_headers_consistency]
enabled = false
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

### ❌ Bad — missing Sec-WebSocket-Key

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
```

### ❌ Bad — HTTP/1.0, where the Upgrade mechanism this handshake needs does not reach

```http
GET /chat HTTP/1.0
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

### ❌ Bad — a version advertisement, which RFC 6455 § 4.4 prints as this exact request

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 25
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

### ❌ Bad — the same subprotocol name twice

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Protocol: chat, superchat, chat
```
