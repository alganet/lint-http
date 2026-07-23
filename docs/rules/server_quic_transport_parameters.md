<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# QUIC Transport Parameters

## Description

Validates that the QUIC transport parameters advertised for HTTP/3 are reasonable. The proxy emits a `QuicTransportParams` event for the parameters **it advertises on its own client-facing HTTP/3 endpoint**, and this rule checks those. It does **not** validate a remote origin's parameters on the upstream leg: the QUIC stack exposes no way to read a peer's transport parameters, so an origin's are not observable and go unchecked here. The checks:

* **Bidirectional streams allowed** — `initial_max_streams_bidi` should be non-zero (RFC 9114 §6.1) so that at least one HTTP/3 request stream can be opened; only an explicit 0 is flagged, not an absent value or a value below the §6.1 floor of 100.
* **Connection flow control** — `initial_max_data` should be non-zero so that data can actually be transferred (a reasonableness check; RFC 9000 §18.2 permits 0, raisable via MAX_DATA).
* **Stream flow control** — the per-stream windows should be non-zero so streams can carry data: `initial_max_stream_data_bidi_remote` for the client's request streams (RFC 9114 §6.1) and `initial_max_stream_data_uni` for the control/QPACK streams (RFC 9114 §6.2). `initial_max_stream_data_bidi_local` governs server-initiated bidirectional streams, which HTTP/3 does not use, so its non-zero check is a reasonableness heuristic.
* **Idle timeout** — `max_idle_timeout_ms` should be set (non-zero) to prevent idle connections from consuming server resources indefinitely, and should not be excessively large (>10 minutes); both are reasonableness heuristics, since 0/absent legally disables the timeout (RFC 9000 §18.2).

## Specifications

- [RFC 9000 §18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2): Transport Parameter Definitions
- [RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1): Bidirectional Streams — servers SHOULD grant non-zero stream and flow-control limits
- [RFC 9114 §6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2): Unidirectional Streams — restricting their flow-control window blocks control/QPACK

## Configuration

```toml
[rules.server_quic_transport_parameters]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
initial_max_streams_bidi = 256
initial_max_data = 4194304       (4 MiB)
max_idle_timeout_ms = 30000         (30 seconds)
initial_max_stream_data_bidi_local = 1048576   (1 MiB)
initial_max_stream_data_bidi_remote = 1048576  (1 MiB)
initial_max_stream_data_uni = 1048576          (1 MiB)
```

### ❌ Bad (zero bidirectional streams)

```http
initial_max_streams_bidi = 0
# Violation: HTTP/3 requires at least one bidirectional stream
```

### ❌ Bad (no idle timeout)

```http
max_idle_timeout = 0
# Violation: connections may remain idle indefinitely
```

### ❌ Bad (excessive idle timeout)

```http
max_idle_timeout = 3600000  (1 hour)
# Violation: excessively large idle timeout wastes server resources
```
