<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_tunnel_port_empty

A CONNECT's destination ends at the colon with no port

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.

## Configuration

```toml
[violations.authority_tunnel_port_empty]
# A CONNECT's destination ends at the colon with no port
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [request_target_form_valid](../rules/request_target_form_valid.md)
