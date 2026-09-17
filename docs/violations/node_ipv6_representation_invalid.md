<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# node_ipv6_representation_invalid

Node identifier writes an IPv6 address outside the recommended representation

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7239 §6.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1): How an `IPv6address` is spelled in a node identifier: always in square brackets, and following RFC 5952's textual representation recommendations

## Configuration

```toml
[violations.node_ipv6_representation_invalid]
# Node identifier writes an IPv6 address outside the recommended representation
severity = "info"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
