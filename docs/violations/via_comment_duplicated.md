<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# via_comment_duplicated

Via member carries more than one comment

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): The `Via` grammar — `Via = #( received-protocol RWS received-by [ RWS comment ] )` — the sentence that puts the field in both directions, and the requirements about forwarding and combining that a single captured message cannot answer

## Configuration

```toml
[violations.via_comment_duplicated]
# Via member carries more than one comment
severity = "warn"
```

## Reported By

- [via_header_syntax](../rules/via_header_syntax.md)
