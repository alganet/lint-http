<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# well_known_name_empty

The reserved prefix carries no name after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615.html#section-3): Well-Known URIs — the definition and its scheme proviso, the `segment-nz` MUST on a registered name, the MAY for additional path components, and the sentence saying a `.well-known` elsewhere in the path is not one

## Configuration

```toml
[violations.well_known_name_empty]
# The reserved prefix carries no name after it
severity = "info"
```

## Reported By

- [well_known_uri_syntax](../rules/well_known_uri_syntax.md)
