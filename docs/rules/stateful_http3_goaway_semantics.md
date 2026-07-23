<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 GOAWAY Semantics

## Description

Validates HTTP/3 GOAWAY frame semantics during connection lifecycle.  A GOAWAY's identifier depends on who sent it: a server sends a client-initiated request stream ID, a client sends a push ID (RFC 9114 §5.2), so the checks below are scoped by sender.  This rule inspects protocol-level events and checks:

* **GOAWAY identifier must not increase** — when multiple GOAWAY frames are received from the same peer on a connection, the identifier in each subsequent GOAWAY MUST NOT be greater than the previous one (RFC 9114 §5.2).
* **No request streams beyond a server GOAWAY limit** — after a *server* GOAWAY (whose identifier is a request stream ID), no new request stream should be opened with an ID greater than the indicated last stream ID (RFC 9114 §5.2).  A client GOAWAY carries a push ID and does not constrain request streams.

## Specifications

- [RFC 9114 §5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2): Connection Shutdown (GOAWAY)

## Configuration

```toml
[rules.stateful_http3_goaway_semantics]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
# Connection accepts streams 0, 4, 8
# Server sends GOAWAY { stream_id: 8 }
# Server sends GOAWAY { stream_id: 4 }  (allowed: decreasing)
# Connection closes gracefully
```

### ❌ Bad (increasing GOAWAY stream ID)

```http
# Server sends GOAWAY { stream_id: 4 }
# Server sends GOAWAY { stream_id: 12 }
# Violation: stream ID 12 increased from previous 4 (RFC 9114 §5.2)
```

### ❌ Bad (stream opened beyond GOAWAY limit)

```http
# Server sends GOAWAY { stream_id: 4 }
# Client opens stream 8
# Violation: stream 8 opened after GOAWAY with last stream ID 4 (RFC 9114 §5.2)
```
