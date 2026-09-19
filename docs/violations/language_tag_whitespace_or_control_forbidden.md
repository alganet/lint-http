<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# language_tag_whitespace_or_control_forbidden

Language tag holds whitespace or a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 5646 §2.1](https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1): Syntax: the `Language-Tag` production, wherever a field or a parameter carries one. Its prose properties are enforced; its subtag ordering and length classes are not

## Configuration

```toml
[violations.language_tag_whitespace_or_control_forbidden]
# Language tag holds whitespace or a control character
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [language_tag_syntax](../rules/language_tag_syntax.md)
- [link_header_valid](../rules/link_header_valid.md)
