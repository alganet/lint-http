<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# node_port_malformed

Node identifier holds something that is not a node-port

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 7239 §6](https://www.rfc-editor.org/rfc/rfc7239.html#section-6): `node` — an IPv4 address, a bracketed IPv6 address, `unknown` or an obfuscated identifier, each optionally followed by a `node-port`

## Configuration

```toml
[violations.node_port_malformed]
# Node identifier holds something that is not a node-port
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
