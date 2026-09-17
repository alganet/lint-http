<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_quoted_pair_malformed

Mailbox escape is not a quoted-pair

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5322 §3.2.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.1): `quoted-pair` — the backslash and the one `VCHAR` or `WSP` it owes

## Configuration

```toml
[violations.mailbox_quoted_pair_malformed]
# Mailbox escape is not a quoted-pair
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
