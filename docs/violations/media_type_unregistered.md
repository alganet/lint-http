<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_unregistered

Media type is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `media-type = type "/" subtype parameters`, both halves `token` and both case-insensitive, and the "ought to be registered with IANA" guidance — guidance rather than a requirement, and not something this crate verifies

## Configuration

```toml
[violations.media_type_unregistered]
# Media type is not one the deployment recognises
severity = "warn"
```

## Reported By

- [content_type_registered](../rules/content_type_registered.md)
