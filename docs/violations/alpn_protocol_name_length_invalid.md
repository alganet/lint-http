<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alpn_protocol_name_length_invalid

ALPN protocol name is longer than the vector that carries it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7301 §3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1): The Application-Layer Protocol Negotiation Extension: protocol names are IANA-registered opaque byte strings, carried in a `ProtocolName` vector of at most 255 octets; §3.2 is the fatal alert a server sends when nothing is in common

## Configuration

```toml
[violations.alpn_protocol_name_length_invalid]
# ALPN protocol name is longer than the vector that carries it
severity = "warn"
```

## Reported By

- [alt_svc_protocol_registered](../rules/alt_svc_protocol_registered.md)
