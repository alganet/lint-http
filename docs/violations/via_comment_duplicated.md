<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# via_comment_duplicated

Via member carries more than one comment

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): The `Via` grammar — `Via = #( received-protocol RWS received-by [ RWS comment ] )` — the sentence that puts the field in both directions, and the requirements about forwarding and combining that a single captured message cannot answer

## Configuration

```toml
[violations.via_comment_duplicated]
# Via member carries more than one comment
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [via_header_syntax](../rules/via_header_syntax.md)
