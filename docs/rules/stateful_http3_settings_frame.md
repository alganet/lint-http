<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 SETTINGS Frame

## Description

Validates HTTP/3 SETTINGS frame semantics on the control stream.  This
rule inspects protocol-level events emitted by the QUIC stream wrapper
and checks:

* **No duplicate SETTINGS** — an endpoint MUST NOT send a SETTINGS frame
  more than once over a connection (RFC 9114 §7.2.4).  A second
  `H3SettingsReceived` event on the same connection is a violation.
* **No reserved HTTP/2 setting identifiers** — setting identifiers that
  were defined in HTTP/2 but have no corresponding HTTP/3 setting are
  reserved.  Their receipt MUST be treated as a connection error of type
  `H3_SETTINGS_ERROR` (RFC 9114 §7.2.4.1).  The reserved identifiers
  are `0x00`, `0x02` (SETTINGS_ENABLE_PUSH), `0x03`
  (SETTINGS_MAX_CONCURRENT_STREAMS), `0x04`
  (SETTINGS_INITIAL_WINDOW_SIZE), and `0x05` (SETTINGS_MAX_FRAME_SIZE).

## Specifications

- [RFC 9114 §7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4) — SETTINGS.
- [RFC 9114 §7.2.4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1) — Defined SETTINGS Parameters.

## Configuration

```toml
[rules.stateful_http3_settings_frame]
enabled = true
severity = "warn"
```

## Examples

### Good

A single SETTINGS frame on the control stream with valid HTTP/3
identifiers:

```
# Control stream sends SETTINGS:
#   SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 8192
#   SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = 4096
#   SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = 100
# No further SETTINGS frames on this connection
```

### Bad (duplicate SETTINGS)

```
# Control stream sends SETTINGS { 0x06 = 8192 }
# Control stream sends SETTINGS { 0x06 = 4096 }
# Violation: duplicate SETTINGS frame on the same connection (RFC 9114 §7.2.4)
```

### Bad (reserved HTTP/2 setting identifier)

```
# Control stream sends SETTINGS { 0x03 = 100 }
# Violation: SETTINGS contains reserved HTTP/2 setting identifier 0x03 (RFC 9114 §7.2.4.1)
```
