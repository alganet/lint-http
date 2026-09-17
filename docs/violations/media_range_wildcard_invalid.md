<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_range_wildcard_invalid

A wildcard type is written beside a concrete subtype

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, and the removal of the extension parameters that once followed the weight

## Configuration

```toml
[violations.media_range_wildcard_invalid]
# A wildcard type is written beside a concrete subtype
severity = "warn"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
