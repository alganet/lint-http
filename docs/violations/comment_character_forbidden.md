<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# comment_character_forbidden

Comment holds a character ctext does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5): Comments — `comment = "(" *( ctext / quoted-pair / comment ) ")"`, the `ctext` class, and the self-reference that makes a comment nestable

## Configuration

```toml
[violations.comment_character_forbidden]
# Comment holds a character ctext does not admit
# GRAMMAR obliges the sender, so this defaults to error.
# No input this tool accepts reaches this defect: a `ctext` violation in a field value is a control octet, and no route carries one to the rules: on the wire the parser refuses the message before there is a transaction, and from a capture file `HeaderValue` refuses the record
severity = "error"
```

## Reported By

- [server_header_product_valid](../rules/server_header_product_valid.md)
- [user_agent_token_valid](../rules/user_agent_token_valid.md)
- [via_header_syntax](../rules/via_header_syntax.md)
