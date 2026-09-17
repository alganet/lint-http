<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_character_forbidden

Content-Length value holds an octet DIGIT does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against

## Configuration

```toml
[violations.content_length_character_forbidden]
# Content-Length value holds an octet DIGIT does not admit
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_length_valid](../rules/content_length_valid.md)
