<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_tunnel_port_missing

A CONNECT's destination names no port

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.

## Configuration

```toml
[violations.authority_tunnel_port_missing]
# A CONNECT's destination names no port
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
