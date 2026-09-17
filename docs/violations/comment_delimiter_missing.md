<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# comment_delimiter_missing

Comment is never closed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §5.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5): Comments — `comment = "(" *( ctext / quoted-pair / comment ) ")"`, the `ctext` class, and the self-reference that makes a comment nestable

## Configuration

```toml
[violations.comment_delimiter_missing]
# Comment is never closed
severity = "warn"
```

## Reported By

- [server_header_product_valid](../rules/server_header_product_valid.md)
- [user_agent_token_valid](../rules/user_agent_token_valid.md)
- [via_header_syntax](../rules/via_header_syntax.md)
