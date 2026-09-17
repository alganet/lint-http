<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# product_missing

A product list opens with something that is not a product

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): Collected ABNF, where `Server` and `User-Agent` are printed as the same production — `product *( RWS ( product / comment ) )` — and neither field's own section restates the other's

## Configuration

```toml
[violations.product_missing]
# A product list opens with something that is not a product
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [server_header_product_valid](../rules/server_header_product_valid.md)
- [user_agent_token_valid](../rules/user_agent_token_valid.md)
