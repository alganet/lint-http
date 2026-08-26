<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Sec Websocket Version Advertisement

## Description

Reads the `Sec-WebSocket-Version` a **response** carries — the versions a server advertises when it will not speak the one the client asked for.

**Two fields share a name and neither shares a production.** RFC 6455 §4.3 prints `Sec-WebSocket-Version-Client = version` for the request and `Sec-WebSocket-Version-Server = 1#version` for the response, and says what the suffixes mean: *ABNF rules with the "-Client" suffix in the name are only used in requests sent by the client to the server; ABNF rules with the "-Server" suffix in the name are only used in responses sent by the server to the client.* So the response's field is a **list** where the request's is one value, and `sec_websocket_headers_consistent` — which reads the request — measures the other production.

**The notation is RFC 2616's, which §4.3 imports by name.** A null list element therefore conforms: `Sec-WebSocket-Version: 13,,8` advertises two versions, where RFC 9110 §5.6.1.1 would make the empty member a sender's defect. What `1#` requires is *at least one non-null element*, so a value that is only commas advertises nothing and is the finding instead. Several field lines in one section are one list — §4.4 prints the same advertisement both ways and calls them the same response.

**The second finding is the field's own reason for existing.** §11.3.5: the field *is also sent from the server to the client on WebSocket handshake error, when the version received from the client does not match a version understood by the server*, and *In such a case, the header field includes the protocol version(s) supported by the server.* A response advertising a list that **contains the version the request asked for** says both things about one handshake: that the server did not understand that version, and that it will speak it. The comparison is exact, because both sides derive from `version`, which is DIGITs — no case to fold, no leading zero to normalise, since the production admits none.

**Not reported: that the field is missing.** §4.4's MUST is conditional — *If the server doesn't support the requested version, it MUST respond with a |Sec-WebSocket-Version| header field … containing all versions it is willing to use* — and its antecedent is a fact about the server, not about the message. A non-101 answer to a handshake can be a refusal for any of the reasons §4.2.2 lists (a 401, a 3xx, a 403, a 404, a 426), and no field in the exchange says which. Reporting every one of them for a missing advertisement would be reading the antecedent off the consequent.

**Not reported: which versions the list should hold, or a `101` that carries one.** The set a server is *willing to use* is the server's own; nothing in the capture disagrees with it. And §11.3.5 describes when the field is sent rather than forbidding it elsewhere, so a `101` carrying it is odd and not a violation — `stateful_websocket_handshake_validity` declines the version question on a `101` for its own reason, which is that §4.2.2 aborts a handshake only for a version *that does not match a version understood by the server*, a fact a `101` is that server asserting.

Scope: this rule reads a response's header section, and only where the request was RFC 6455's opening handshake — the same shared gate the other two handshake rules use. Above HTTP/1.x the handshake is an extended CONNECT (RFC 8441, RFC 9220) and this field is not part of it. A value carrying an octet outside US-ASCII is measured rather than skipped: it reaches the production that excludes it and is reported there.

## Specifications

- [RFC 6455 §4.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3): Collected ABNF — `Sec-WebSocket-Version-Server = 1#version`, the `version` production under it, the suffix convention that makes this field the response's, and the note that the notation is RFC 2616's
- [RFC 2616 §2.1](https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1): Augmented BNF — the `#rule` §4.3 imports: null elements are allowed (RFC 9110 §5.6.1.1 forbids them) and `1#` requires one that is not. Obsolete and correct: the current document is what sends the reader here
- [RFC 6455 §4.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.4): Supporting Multiple Versions — the conditional MUST whose antecedent is the server's own state, and the worked example printing one advertisement as one field line and as two
- [RFC 6455 §11.3.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.5): The field's registration — when a server sends it, and that it holds the versions the server supports, which is what a list holding the requested one contradicts

## Configuration

```toml
[rules.server_sec_websocket_version_advertisement]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good §4.4's own worked exchange

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 25

HTTP/1.1 400 Bad Request
Sec-WebSocket-Version: 13, 8, 7
```

### ✅ Good The same advertisement on two field lines, which §4.4 also prints

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 25

HTTP/1.1 400 Bad Request
Sec-WebSocket-Version: 13
Sec-WebSocket-Version: 8, 7
```

### ❌ Bad A member deriving from no `version` — the production admits no leading zero

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 25

HTTP/1.1 400 Bad Request
Sec-WebSocket-Version: 013
```

### ❌ Bad The advertisement holds the version the request asked for

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 25

HTTP/1.1 400 Bad Request
Sec-WebSocket-Version: 13, 25
```
