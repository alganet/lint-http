<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_suffix_empty

A media type subtype ends in a bare plus

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2): Naming Requirements: `restricted-name`, which decides where a suffix starts ("characters after last plus") and that a name must begin with ALPHA or DIGIT — so a subtype that is only a suffix has no base name

## Configuration

```toml
[violations.media_type_suffix_empty]
# A media type subtype ends in a bare plus
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [media_type_suffix_valid](../rules/media_type_suffix_valid.md)
