<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 SETTINGS Frame

## Description

Validates HTTP/3 SETTINGS frame semantics on the control stream.  This rule inspects protocol-level events emitted by the QUIC stream wrapper and checks:

* **No duplicate SETTINGS** — a SETTINGS frame MUST be sent as the first frame of each control stream by each peer, and it MUST NOT be sent subsequently (RFC 9114 §7.2.4).  SETTINGS applies to the entire connection, never a single stream, so a second `H3SettingsReceived` event *from the same peer* on the connection is a violation.  Because the obligation is per peer, the other peer's SETTINGS (observable on the upstream leg) is its own legitimate first frame, not a duplicate.
* **No reserved setting identifiers** — the `Reserved` rows of the "HTTP/3 Settings" registry (RFC 9114 Table 3, §11.2.2) MUST NOT be sent, and their receipt MUST be treated as a connection error of type `H3_SETTINGS_ERROR` (RFC 9114 §7.2.4.1).  The reserved identifiers are `0x00` (no HTTP/2 counterpart), `0x02` (SETTINGS_ENABLE_PUSH in HTTP/2), `0x03` (SETTINGS_MAX_CONCURRENT_STREAMS), `0x04` (SETTINGS_INITIAL_WINDOW_SIZE), and `0x05` (SETTINGS_MAX_FRAME_SIZE).

* **No repeated setting identifier** — the same setting identifier MUST NOT occur more than once in the SETTINGS frame (RFC 9114 §7.2.4).  A receiver MAY treat duplicates as a connection error of type `H3_SETTINGS_ERROR`; the sender's obligation is unconditional, so a repeated identifier within one frame is a violation.

Identifiers outside the reserved set — including the `0x1f * N + 0x21` greasing values and unregistered extensions — are ignored, per RFC 9114 §7.2.4's requirement that unknown parameters be ignored.

## Specifications

- [RFC 9114 §7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4): SETTINGS
- [RFC 9114 §7.2.4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1): Defined SETTINGS Parameters
- [RFC 9114 §11.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-11.2.2): Settings Parameters (Table 3: the Reserved rows)

## Configuration

```toml
[rules.stateful_http3_settings_frame]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
# Control stream sends SETTINGS:
#   SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 8192
#   SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = 4096
#   SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = 100
# No further SETTINGS frames on this connection
```

### ❌ Bad (duplicate SETTINGS)

```http
# Control stream sends SETTINGS { 0x06 = 8192 }
# Control stream sends SETTINGS { 0x06 = 4096 }
# Violation: duplicate SETTINGS frame on the same connection (RFC 9114 §7.2.4)
```

### ❌ Bad (reserved HTTP/2 setting identifier)

```http
# Control stream sends SETTINGS { 0x03 = 100 }
# Violation: SETTINGS contains reserved HTTP/2 setting identifier 0x03 (RFC 9114 §7.2.4.1)
```

### ❌ Bad (repeated setting identifier)

```http
# Control stream sends SETTINGS { 0x06 = 8192, 0x06 = 4096 }
# Violation: SETTINGS contains setting identifier 0x06 more than once (RFC 9114 §7.2.4)
```
