<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 GOAWAY Semantics

## Description

Validates HTTP/3 GOAWAY frame semantics during connection lifecycle.  This
rule inspects protocol-level events and checks:

* **GOAWAY stream ID must not increase** — when multiple GOAWAY frames are
  received on the same connection, the stream ID in each subsequent GOAWAY
  MUST NOT be greater than the previous one (RFC 9114 §5.2).
* **No streams beyond GOAWAY limit** — after a GOAWAY frame is received,
  no new request streams should be opened with an ID greater than the
  indicated last stream ID (RFC 9114 §5.2).

## Specifications

- [RFC 9114 §5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2) — Connection Shutdown (GOAWAY).

## Configuration

```toml
[rules.stateful_http3_goaway_semantics]
enabled = true
severity = "warn"
```

## Examples

### Good

A server sends GOAWAY indicating stream 8 is the last it will process.
No further streams are opened beyond that limit, and a subsequent GOAWAY
lowers the stream ID.  Client-initiated bidirectional stream IDs in QUIC
increment by 4 starting at 0 (RFC 9000 §2.1):

```
# Connection accepts streams 0, 4, 8
# Server sends GOAWAY { stream_id: 8 }
# Server sends GOAWAY { stream_id: 4 }  (allowed: decreasing)
# Connection closes gracefully
```

### Bad (increasing GOAWAY stream ID)

```
# Server sends GOAWAY { stream_id: 4 }
# Server sends GOAWAY { stream_id: 12 }
# Violation: stream ID 12 increased from previous 4 (RFC 9114 §5.2)
```

### Bad (stream opened beyond GOAWAY limit)

```
# Server sends GOAWAY { stream_id: 4 }
# Client opens stream 8
# Violation: stream 8 opened after GOAWAY with last stream ID 4 (RFC 9114 §5.2)
```
