<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# QUIC Transport Parameters

## Description

Validates that QUIC transport parameters negotiated during the handshake are
reasonable for HTTP/3 usage.  This rule inspects protocol-level
`QuicTransportParams` events and checks:

* **Bidirectional streams allowed** — `initial_max_streams_bidi` must be
  non-zero so that at least one HTTP/3 request stream can be opened.
* **Connection flow control** — `initial_max_data` must be non-zero so that
  data can actually be transferred.
* **Stream flow control** — `initial_max_stream_data_bidi_local`,
  `initial_max_stream_data_bidi_remote`, and `initial_max_stream_data_uni`
  must be non-zero for their respective stream types to carry data.
* **Idle timeout** — `max_idle_timeout_ms` should be set (non-zero) to prevent
  idle connections from consuming server resources indefinitely, and should
  not be excessively large (>10 minutes).

## Specifications

- [RFC 9000 §18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2) — Transport Parameter Definitions.
- [RFC 9114 §3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1) — Discovering an HTTP/3 Endpoint.

## Configuration

```toml
[rules.server_quic_transport_parameters]
enabled = true
severity = "warn"
```

## Examples

### Good

A server advertises transport parameters that allow HTTP/3 operation:

```
initial_max_streams_bidi = 256
initial_max_data = 4194304       (4 MiB)
max_idle_timeout_ms = 30000         (30 seconds)
initial_max_stream_data_bidi_local = 1048576   (1 MiB)
initial_max_stream_data_bidi_remote = 1048576  (1 MiB)
initial_max_stream_data_uni = 1048576          (1 MiB)
```

### Bad (zero bidirectional streams)

```
initial_max_streams_bidi = 0
# Violation: HTTP/3 requires at least one bidirectional stream
```

### Bad (no idle timeout)

```
max_idle_timeout = 0
# Violation: connections may remain idle indefinitely
```

### Bad (excessive idle timeout)

```
max_idle_timeout = 3600000  (1 hour)
# Violation: excessively large idle timeout wastes server resources
```
