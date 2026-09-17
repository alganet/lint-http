<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_member_malformed

Link member carries content the production does not continue with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 8288 §3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3): The serialisation: `Link = #link-value`, the angle-bracketed `URI-Reference`, and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]` — whose optional group is what makes a valueless parameter conforming. Also the sentence equating the token and quoted-string forms, which is why a value is judged after unquoting

## Configuration

```toml
[violations.link_member_malformed]
# Link member carries content the production does not continue with
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
