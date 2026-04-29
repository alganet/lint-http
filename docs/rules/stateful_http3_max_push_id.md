<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 MAX_PUSH_ID Monotonicity

## Description

Validates HTTP/3 `MAX_PUSH_ID` frame semantics across the lifetime of a
connection.  This rule inspects protocol-level events emitted by the
HTTP/3 control-stream parser and checks:

* **MAX_PUSH_ID must not decrease** — when multiple `MAX_PUSH_ID` frames
  are received on the same connection, each successive value MUST be
  greater than or equal to the previous one.  Receipt of a smaller value
  is a connection error of type `H3_ID_ERROR` (RFC 9114 §7.2.7).

The first `MAX_PUSH_ID` on a connection establishes the initial limit and
is always accepted, regardless of value (zero is valid and means the
server is not allowed to push).

## Specifications

- [RFC 9114 §7.2.7](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7) — `MAX_PUSH_ID` frame.
- [RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1) — HTTP/3 error codes (`H3_ID_ERROR`).

## Configuration

```toml
[rules.stateful_http3_max_push_id]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

A client raises the push limit over time as it discovers it can handle
more pushed responses:

```
# Client sends MAX_PUSH_ID { push_id: 0 }   (no pushes yet)
# Client sends MAX_PUSH_ID { push_id: 10 }  (raise limit)
# Client sends MAX_PUSH_ID { push_id: 10 }  (idempotent re-send: allowed)
# Client sends MAX_PUSH_ID { push_id: 25 }  (raise further: allowed)
```

### ❌ Bad (decreasing MAX_PUSH_ID)

```
# Client sends MAX_PUSH_ID { push_id: 10 }
# Client sends MAX_PUSH_ID { push_id: 4 }
# Violation: MAX_PUSH_ID 4 decreased from previous 10 (RFC 9114 §7.2.7, H3_ID_ERROR)
```
