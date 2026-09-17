<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_member_malformed

Link member carries content the production does not continue with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8288 §3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3): The serialisation: `Link = #link-value`, the angle-bracketed `URI-Reference`, and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]` — whose optional group is what makes a valueless parameter conforming. Also the sentence equating the token and quoted-string forms, which is why a value is judged after unquoting

## Configuration

```toml
[violations.link_member_malformed]
# Link member carries content the production does not continue with
severity = "warn"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
