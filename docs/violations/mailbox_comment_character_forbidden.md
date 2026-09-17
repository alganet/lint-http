<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_comment_character_forbidden

Mailbox comment holds a character outside ctext

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5322 §3.2.2](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.2): `CFWS`, `comment` and `ctext` — the comment names itself, so what it holds is balanced and its character class stops at %x7E

## Configuration

```toml
[violations.mailbox_comment_character_forbidden]
# Mailbox comment holds a character outside ctext
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
