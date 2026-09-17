<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_relation_type_malformed

Link names a relation type that is neither registered-shaped nor a URI

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 8288 §3.3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3): `rel` MUST be present and MUST NOT appear more than once; its value is `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The section that makes a URI-shaped relation type conforming and a capital letter in a registered one not

## Configuration

```toml
[violations.link_relation_type_malformed]
# Link names a relation type that is neither registered-shaped nor a URI
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
