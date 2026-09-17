<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# quic_request_stream_limit_invalid

QUIC parameters leave no room for an HTTP/3 request stream

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1): Bidirectional Streams — an HTTP/3 server SHOULD configure non-zero minimums for the number of permitted streams and the initial stream flow-control window, and HTTP/3 does not use server-initiated bidirectional streams

## Configuration

```toml
[violations.quic_request_stream_limit_invalid]
# QUIC parameters leave no room for an HTTP/3 request stream
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [quic_transport_parameters_valid](../rules/quic_transport_parameters_valid.md)
