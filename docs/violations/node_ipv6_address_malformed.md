<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# node_ipv6_address_malformed

Node identifier brackets something that is not an IPv6 address

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7239 §6](https://www.rfc-editor.org/rfc/rfc7239.html#section-6): `node` — an IPv4 address, a bracketed IPv6 address, `unknown` or an obfuscated identifier, each optionally followed by a `node-port`

## Configuration

```toml
[violations.node_ipv6_address_malformed]
# Node identifier brackets something that is not an IPv6 address
severity = "warn"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
