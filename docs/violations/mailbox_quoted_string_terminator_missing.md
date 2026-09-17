<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_quoted_string_terminator_missing

Mailbox quoted-string is never closed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5322 §3.2.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4): `quoted-string` and `qtext` — the quoted alternative, and the class it admits between the two DQUOTEs

## Configuration

```toml
[violations.mailbox_quoted_string_terminator_missing]
# Mailbox quoted-string is never closed
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
