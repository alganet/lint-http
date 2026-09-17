<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_range_parameter_forbidden

Accept member writes a parameter after the weight

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, and the removal of the extension parameters that once followed the weight

## Configuration

```toml
[violations.media_range_parameter_forbidden]
# Accept member writes a parameter after the weight
severity = "warn"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
