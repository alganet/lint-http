<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket Frame Masking

## Description

Reports a client frame that is not masked, and a server frame that is.

**Two MUSTs about one bit, and the sender decides which applies.** RFC 6455 §5.1: *a client MUST mask all frames that it sends to the server* — for the reason the same sentence gives, that an unmasked payload confuses network intermediaries such as intercepting proxies (§10.3 is the attack) — and, three sentences later, *A server MUST NOT mask any frames that it sends to the client.* They are exact opposites, so no frame is measured against both. Each has a recipient's MUST beside it: a server *MUST close the connection upon receiving a frame that is not masked*, and a client *MUST close a connection if it detects a masked frame*, which is why the findings say what the peer is required to do about it.

**Neither MUST has an escape clause.** The reserved bits next door are zero *unless an extension is negotiated*, and `websocket_frame_rsv_bits` reads the handshake for exactly that reason; §5.8 hands extensions the reserved bits, the reserved opcodes and the Extension data field, and says nothing about the MASK bit. §5.1's own parenthetical — *(These rules might be relaxed in a future specification.)* — is about a future document rather than about anything this one lets two endpoints agree, so this rule does not read the negotiation at all.

**A frame whose MASK bit was not recorded is not measured.** The bit is `None` unless the capture read a frame header: tokio-tungstenite hands the relay assembled messages, which have no header, so only the raw-frame path answers it. Every event written before the field existed reads back as `None` too. Reading that as *not masked* would turn every such record into a finding against a client — a claim about the wire made from a gap in the record, which is the one direction that must not be guessed.

**Where these findings come from.** The relay reads frames through tokio-tungstenite, which enforces both sentences before the proxy is handed a message: tungstenite 0.30.0 returns `ProtocolError::UnmaskedFrameFromClient` from its frame reader on the `Role::Server` side (`protocol/frame/mod.rs`) and `ProtocolError::MaskedFrameFromServer` from the `Role::Client` side (`protocol/mod.rs`). So these findings are reachable through `lint`, over capture files written by something other than this proxy — a capture is a record of what was on the wire, and this is the rule that reads it.

**Not reported: the masking key itself.** §5.3 has the client pick a *fresh masking key* per frame, derived from a *strong source of entropy*, and unpredictable from the previous one — the key is not recorded, and unpredictability is not a property of one observation anyway. Nor is any payload unmasked and re-checked: the capture holds the message the relay assembled, not the octets as framed.

## Specifications

- [RFC 6455 §5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1): Overview — both masking MUSTs, the reason the client's exists, and the two recipient MUSTs that say what a conforming peer does about a breach
- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2): Base Framing Protocol — the MASK bit itself: what it means, and that a masking key is present exactly when it is set
- [RFC 6455 §5.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.3): Client-to-Server Masking — the key's own requirements, which a capture holding no key cannot measure
- [RFC 6455 §10.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-10.3): Attacks On Infrastructure (Masking) — why the client's MUST is there, and why an intercepting proxy is the party it protects

## Configuration

```toml
[rules.websocket_frame_masking]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The two directions, each as its own sentence requires

```http
client -> server: opcode=1 FIN=1 MASK=1
server -> client: opcode=1 FIN=1 MASK=0
```

### ❌ Bad A client frame with the bit clear — the server must close the connection

```http
client -> server: opcode=1 FIN=1 MASK=0
```

### ❌ Bad A server frame with the bit set — the client must close the connection

```http
server -> client: opcode=1 FIN=1 MASK=1
```
