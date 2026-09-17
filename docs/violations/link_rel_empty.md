<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_rel_empty

Link member writes a rel with no relation type in it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8288 §3.3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3): `rel` MUST be present and MUST NOT appear more than once; its value is `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The section that makes a URI-shaped relation type conforming and a capital letter in a registered one not

## Configuration

```toml
[violations.link_rel_empty]
# Link member writes a rel with no relation type in it
severity = "warn"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
