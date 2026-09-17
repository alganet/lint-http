<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_tunnel_missing

A CONNECT names no host and port to open a tunnel to

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5): The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them
- [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4): The CONNECT Method — the MUST that a CONNECT request be constructed with `:scheme` and `:path` omitted and `:authority` carrying the host and port to connect to, and the sentence making a request that does not malformed

## Configuration

```toml
[violations.authority_tunnel_missing]
# A CONNECT names no host and port to open a tunnel to
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
