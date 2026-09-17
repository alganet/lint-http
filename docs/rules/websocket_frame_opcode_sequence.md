<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# WebSocket Frame Opcode Sequence

## Description

Reads each WebSocket frame the relay observed and asks three groups of questions, in the order a receiving endpoint reaches them.

**What the opcode is.** The opcode field is four bits, so a recorded value above 15 is one no frame header carried (RFC 6455 §11.8 gives the field its range).  Opcodes 3-7 are reserved for further non-control frames and 11-15 for further control frames; a frame carrying one denotes no frame type the document defines, and §5.2 has the receiving endpoint fail the connection on an unknown opcode.

**What the frame's class requires of it.** §5.5 identifies a control frame by the high bit of its opcode and then states two things about it in one sentence: its payload is 125 bytes or less, and it is never fragmented — so a control frame with the FIN bit clear is reported alongside an oversized one.  A Close frame's body is optional, but a body that exists opens with a two-byte status code, so a Close carrying exactly one payload byte is too short to be either.

**What the frames before it allow.** Once an endpoint has sent a Close, §5.5.1 ends what it may send; a data frame — continuation, Text or Binary — following that endpoint's own Close is reported, and the other direction is left alone, since it is still finishing the closing handshake.  §5.4's fragmentation rules supply the rest: a continuation frame with no fragmented message open in that direction has nothing to continue, and a Text or Binary frame arriving while one is still open interleaves two messages.  Control frames are stepped over when answering that question, because §5.4 permits them in the middle of a fragmented message.

**The escape clause, and when it is in evidence.** §5.8 hands opcodes 3-7 and 11-15, and the reserved bits, to extensions negotiated in the opening handshake, and §5.4's interleaving rule has the same escape.  Each frame event now records what the `101` accepted in `Sec-WebSocket-Extensions`, so a session that accepted an extension stands those three findings down — the opcode may have been given a meaning this document does not define, and deciding which is that extension's document's business.  A capture that does not record the handshake — every one written before the field existed, and every one written by something other than this proxy — is measured exactly as before: reading its silence as *no extension* would invent evidence, and reading it as *some extension* would silence findings this rule has always made.  The reserved bits are `websocket_frame_rsv_bits`'s, on the same three-state reading.

**Where these findings come from.** The relay forwards bytes and records each frame as the wire spelled it — reserved opcodes, control frames with FIN clear, and fragmentation included — so these findings arrive live off this proxy's own relay, and equally through `lint-captures` over any capture that recorded frames.

## Violations

- [websocket_frame_close_body_malformed](../violations/websocket_frame_close_body_malformed.md) — A Close body is too short to hold the status code it opens with
- [websocket_frame_continuation_unsolicited](../violations/websocket_frame_continuation_unsolicited.md) — A continuation frame has no fragmented message to continue
- [websocket_frame_control_fragmentation_forbidden](../violations/websocket_frame_control_fragmentation_forbidden.md) — A control frame is fragmented
- [websocket_frame_control_payload_invalid](../violations/websocket_frame_control_payload_invalid.md) — A control frame carries more payload than its class allows
- [websocket_frame_data_after_close_forbidden](../violations/websocket_frame_data_after_close_forbidden.md) — A data frame follows the same endpoint's Close frame
- [websocket_frame_message_interleaving_forbidden](../violations/websocket_frame_message_interleaving_forbidden.md) — A second message opens while a fragmented one is unterminated
- [websocket_frame_opcode_malformed](../violations/websocket_frame_opcode_malformed.md) — The recorded opcode does not fit the four bits the header holds
- [websocket_frame_opcode_unregistered](../violations/websocket_frame_opcode_unregistered.md) — The opcode is in a reserved range and denotes no frame type

## Specifications

- [RFC 6455 §5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1): Overview: when an endpoint may transmit a data frame
- [RFC 6455 §5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2): Base Framing Protocol — the opcode definitions, the two reserved ranges and what each is reserved for, and the MUST-fail a receiving endpoint owes an unknown opcode
- [RFC 6455 §5.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.4): Fragmentation — what a fragmented message is made of, the MUST NOT against fragmenting a control frame stated in its own right, and the MUST NOT against interleaving two messages with its extension escape
- [RFC 6455 §5.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5): Control Frames — the class test, and the sentence bounding a control frame's payload at 125 bytes
- [RFC 6455 §5.5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1): Close — the body is optional, a body that exists opens with a two-byte status code, and a sender's own Close ends what it may send
- [RFC 6455 §5.6](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.6): Data Frames: the class test for the sequence questions
- [RFC 6455 §5.8](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.8): Extensibility: what the reserved opcodes are reserved for
- [RFC 6455 §11.8](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.8): WebSocket Opcode Registry — the field's range, and the Standards Action policy that makes an unassigned value one no deployment can outrun

## Configuration

```toml
[rules.websocket_frame_opcode_sequence]
enabled = true
```

## Examples

### ✅ Good

```http
# Frames relayed after a WebSocket upgrade, one line each.  The Ping
# sits inside the client's fragmented message, which RFC 6455 §5.4 permits:
# Client -> Server: opcode=1 (Text), FIN=0, 42 bytes
# Client -> Server: opcode=9 (Ping), FIN=1, 0 bytes
# Client -> Server: opcode=0 (Continuation), FIN=1, 17 bytes
# Server -> Client: opcode=8 (Close), FIN=1, 2 bytes
# Client -> Server: opcode=8 (Close), FIN=1, 2 bytes
```

### ❌ Bad (reserved opcode)

```http
# Client -> Server: opcode=5, FIN=1, 10 bytes
# 5 is reserved for further non-control frames (RFC 6455 §5.2)
```

### ❌ Bad (control frame too large)

```http
# Client -> Server: opcode=9 (Ping), FIN=1, 200 bytes
# A control frame's payload is 125 bytes or less (RFC 6455 §5.5)
```

### ❌ Bad (fragmented control frame)

```http
# Server -> Client: opcode=10 (Pong), FIN=0, 4 bytes
# A control frame is never fragmented (RFC 6455 §5.5)
```

### ❌ Bad (continuation with nothing to continue)

```http
# Client -> Server: opcode=1 (Text), FIN=1, 12 bytes
# Client -> Server: opcode=0 (Continuation), FIN=1, 8 bytes
# The previous message was already terminated (RFC 6455 §5.4)
```

### ❌ Bad (interleaved messages)

```http
# Client -> Server: opcode=1 (Text), FIN=0, 12 bytes
# Client -> Server: opcode=2 (Binary), FIN=1, 30 bytes
# The Text message was never terminated (RFC 6455 §5.4)
```

### ❌ Bad (data after close)

```http
# Client -> Server: opcode=8 (Close), FIN=1, 2 bytes
# Client -> Server: opcode=1 (Text), FIN=1, 50 bytes
# A Close ends what that endpoint may send (RFC 6455 §5.5.1)
```
