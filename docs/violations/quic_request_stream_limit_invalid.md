<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# quic_request_stream_limit_invalid

QUIC parameters leave no room for an HTTP/3 request stream

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1): Bidirectional Streams — an HTTP/3 server SHOULD configure non-zero minimums for the number of permitted streams and the initial stream flow-control window, and HTTP/3 does not use server-initiated bidirectional streams

## Configuration

```toml
[violations.quic_request_stream_limit_invalid]
# QUIC parameters leave no room for an HTTP/3 request stream
severity = "warn"
```

## Reported By

- [quic_transport_parameters_valid](../rules/quic_transport_parameters_valid.md)
