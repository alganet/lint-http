<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# language_tag_edge_hyphen_forbidden

Language tag starts or ends with a hyphen

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5646 §2.1](https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1): Syntax: the `Language-Tag` production, wherever a field or a parameter carries one. Its prose properties are enforced; its subtag ordering and length classes are not

## Configuration

```toml
[violations.language_tag_edge_hyphen_forbidden]
# Language tag starts or ends with a hyphen
severity = "warn"
```

## Reported By

- [language_tag_syntax](../rules/language_tag_syntax.md)
- [link_header_valid](../rules/link_header_valid.md)
