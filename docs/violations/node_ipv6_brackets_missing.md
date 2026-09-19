<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# node_ipv6_brackets_missing

Node identifier holds an IPv6 address without its square brackets

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 7239 §6.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1): How an `IPv6address` is spelled in a node identifier: always in square brackets, and following RFC 5952's textual representation recommendations

## Configuration

```toml
[violations.node_ipv6_brackets_missing]
# Node identifier holds an IPv6 address without its square brackets
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
