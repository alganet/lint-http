<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# quic_connection_flow_control_invalid

QUIC parameters advertise no connection-level flow control

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9000 §18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2): Transport Parameter Definitions — what each initial limit means, and that a zero or absent value is legal with a defined effect rather than a defect

## Configuration

```toml
[violations.quic_connection_flow_control_invalid]
# QUIC parameters advertise no connection-level flow control
severity = "warn"
```

## Reported By

- [quic_transport_parameters_valid](../rules/quic_transport_parameters_valid.md)
