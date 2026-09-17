<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_rel_malformed

Link rel value opens or closes on a space

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 8288 §3.3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3): `rel` MUST be present and MUST NOT appear more than once; its value is `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The section that makes a URI-shaped relation type conforming and a capital letter in a registered one not

## Configuration

```toml
[violations.link_rel_malformed]
# Link rel value opens or closes on a space
severity = "warn"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
