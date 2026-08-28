<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket Frame Reserved Bits

## Description

Reports a WebSocket frame whose RSV1, RSV2 or RSV3 bit is set in a session whose opening handshake accepted no extension.

**The requirement is conditional, and the condition is not in the frame.** RFC 6455 §5.2 says each reserved bit *MUST be 0 unless an extension is negotiated that defines meanings for non-zero values*, and — for the other party — *If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_.* §5.8 is what hands the bits to extensions, and it requires the negotiation to happen in the opening handshake. That handshake is an HTTP exchange, and a frame-level rule is handed protocol events rather than transactions — so until the capture carried the answer, the only honest reading of a non-zero bit was *no reading*: `permessage-deflate` (RFC 7692) sets RSV1 on every compressed frame, and a rule reporting the bit alone would report ordinary traffic.

**What changed is the capture, not the sentence.** Each frame event now records what the `101` accepted in `Sec-WebSocket-Extensions`, and §9.1 is why the *server's* field is the whole of the agreement: *The extensions listed by the server in response represent the extensions actually in use for the connection*, and a client *MUST NOT use them unless the server indicates that it wishes to use the extension*. So a `101` carrying no such field settles that nothing can give a non-zero bit a meaning, and the sentence closes.

**Three states, three verdicts.** A handshake that accepted **no** extension is the finding above. A handshake that accepted **one** draws nothing: which bit that extension defines is its own document's business, and deciding it here would mean this rule reading RFC 7692 for RFC 6455. A capture that does **not record** the handshake also draws nothing — every capture written before this field existed, and every one written by something other than this proxy — because the antecedent is then not in evidence in either direction. Silence there is the same decision as silence under an accepted extension, reached for a different reason, and it is why enabling this rule cannot make old captures noisy.

**One finding does not wait for the handshake.** The header prints the three bits as *1 bit each*, so a recorded value above `0b111` is a claim about the record rather than about the wire — no frame header has room for it, and no negotiation could license one. That is the sibling shape of `websocket_frame_opcode_sequence`'s opcode above 15.

**Where these findings come from.** The relay forwards bytes and records each frame's reserved bits as the wire spelled them, so these findings arrive live off this proxy's own relay — and equally through `lint`, over any capture that recorded the bits: a capture is a record of what was on the wire.

**Not reported: what the bits mean when an extension is negotiated.** Whether the accepted extension actually defines the bit that was set, whether the extension was one the client offered, and whether the `Sec-WebSocket-Extensions` value derives from §9.1's `extension-list` grammar are three other questions; the second is `websocket_handshake_valid`'s and the third is `sec_websocket_extensions_syntax`'s.

## Specifications

- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2): Base Framing Protocol — the three reserved bits, their width, the conditional MUST on the sender and the MUST-fail on the recipient
- [RFC 6455 §5.8](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.8): Extensibility — what the reserved bits are reserved for, and that the negotiation happens in the opening handshake
- [RFC 6455 §9.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1): Negotiating Extensions — why the server's response field is the whole of the agreement, and the client's own field only an offer

## Configuration

```toml
[rules.websocket_frame_rsv_bits]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good No extension accepted, and the bits are zero

```http
101 Switching Protocols (no Sec-WebSocket-Extensions)
frame: opcode=1 FIN=1 RSV=000
```

### ✅ Good RSV1 under an extension that was accepted — permessage-deflate's compressed frame

```http
101 Switching Protocols
Sec-WebSocket-Extensions: permessage-deflate

frame: opcode=1 FIN=1 RSV=100
```

### ❌ Bad The same bit, with nothing negotiated to give it a meaning

```http
101 Switching Protocols (no Sec-WebSocket-Extensions)
frame: opcode=1 FIN=1 RSV=100
```

### ❌ Bad A value the three-bit field has no room for

```http
101 Switching Protocols (no Sec-WebSocket-Extensions)
frame: opcode=1 FIN=1 RSV=1000
```
