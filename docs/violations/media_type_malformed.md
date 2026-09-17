<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_malformed

Media type is not a type/subtype pair

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `media-type = type "/" subtype parameters`, both halves `token` and both case-insensitive, and the "ought to be registered with IANA" guidance — guidance rather than a requirement, and not something this crate verifies

## Configuration

```toml
[violations.media_type_malformed]
# Media type is not a type/subtype pair
severity = "warn"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [content_type_valid](../rules/content_type_valid.md)
