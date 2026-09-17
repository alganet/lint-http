<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_suffix_empty

A media type subtype ends in a bare plus

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2): Naming Requirements: `restricted-name`, which decides where a suffix starts ("characters after last plus") and that a name must begin with ALPHA or DIGIT — so a subtype that is only a suffix has no base name

## Configuration

```toml
[violations.media_type_suffix_empty]
# A media type subtype ends in a bare plus
severity = "warn"
```

## Reported By

- [media_type_suffix_valid](../rules/media_type_suffix_valid.md)
